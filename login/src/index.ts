// login/src/index.ts
//
// GitHub-OIDC -> Polaris access-token exchange.
//
// Implements the GitHub Action described in RFC 030 (§5) "The
// croonix/polaris-actions repository": request a GitHub Actions OIDC
// id_token, exchange it with a Polaris instance's github-oidc endpoint,
// mask + surface the minted access token, and optionally export
// TF_TOKEN_<host> for subsequent tofu/terraform steps.

import * as core from '@actions/core'

// ---------------------------------------------------------------------------
// TF_TOKEN_<host> env var name (R-11 CORRECTED)
// ---------------------------------------------------------------------------

/**
 * Derives the OpenTofu/Terraform CLI credential env var name for a given
 * host: `TF_TOKEN_` + host AS-IS (no uppercasing) + `.` -> `_`, `-` -> `__`.
 *
 * Per OpenTofu's own docs (verified against rev-2's now-corrected rule):
 * the host is NOT uppercased, dots become single underscores, and hyphens
 * become DOUBLE underscores (since a single underscore would collide with
 * a dot's mangling and make two distinct hosts produce the same env var).
 *
 * A non-default port's colon is left unmangled — not a valid POSIX env var
 * name, but deterministic; OpenTofu's docs do not cover this case.
 */
export function tfTokenEnvName(host: string): string {
  const mangled = host.replaceAll('.', '_').replaceAll('-', '__')
  return `TF_TOKEN_${mangled}`
}

// ---------------------------------------------------------------------------
// Audience canonicalization — IDENTICAL algorithm to Warden's
// CanonicalizeAudience (polaris/services/identity/internal/config/config.go).
// ---------------------------------------------------------------------------

/**
 * Canonicalizes an audience host string to RFC 030 D-16's canonical form:
 * lowercase, bare host with no scheme, default port (443/80) omitted,
 * non-default port retained, IDN encoded as punycode.
 *
 * MUST stay byte-for-byte compatible with Warden's Go implementation — see
 * config.go's CanonicalizeAudience — since the exchange this feeds is an
 * EXACT equality check against a single configured value. Rejects
 * ASCII-only-Punycode labels (the GO-2026-5026 / CVE-2026-39821 class):
 * the WHATWG URL parser's IDNA handling already rejects an `xn--` label
 * that decodes to pure ASCII, mirroring Go's idna.Lookup.ToASCII behavior
 * this function depends on.
 */
export function canonicalizeAudienceHost(raw: string): string {
  const trimmed = raw.trim()
  if (trimmed === '') {
    throw new Error('audience host is empty')
  }

  // Strip a scheme if present; otherwise assume one so the WHATWG URL
  // parser can split host/port for us. The canonical form is a bare host,
  // so "https://polaris.example/" and "polaris.example" must not diverge.
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`

  let url: URL
  try {
    url = new URL(withScheme)
  } catch {
    throw new Error(`invalid audience host: ${raw}`)
  }

  const hostname = url.hostname
  if (hostname === '') {
    throw new Error(`audience host has no host component: ${raw}`)
  }

  const port = url.port
  if (port !== '' && port !== '443' && port !== '80') {
    return `${hostname}:${port}`
  }
  return hostname
}

// ---------------------------------------------------------------------------
// Audience derivation
// ---------------------------------------------------------------------------

/**
 * Derives the OIDC audience to request: an explicit non-empty `audience`
 * input wins verbatim (it may legitimately be the literal fallback string
 * "polaris" and must never be run through canonicalization). Otherwise,
 * the canonicalized host of `polarisUrl` is used. There is no static
 * default in action.yml by design (D-16).
 */
export function deriveAudience(polarisUrl: string, explicitAudience?: string): string {
  if (explicitAudience !== undefined && explicitAudience !== '') {
    return explicitAudience
  }
  return canonicalizeAudienceHost(polarisUrl)
}

// ---------------------------------------------------------------------------
// GitHub OIDC -> Polaris token exchange
// ---------------------------------------------------------------------------

export interface ExchangeSuccess {
  accessToken: string
  tokenType: string
  expiresIn: number
  account: string
  role: string
}

interface ExchangeErrorBody {
  error?: string
  error_description?: string
}

/**
 * Thrown for any terminal (non-retryable) failure of the exchange request:
 * any 4xx other than a 429/503 with a `Retry-After` header.
 */
export class GithubOidcExchangeError extends Error {
  readonly code: string
  readonly httpStatus: number

  constructor(code: string, description: string, httpStatus: number) {
    super(`${code}: ${description}`)
    this.name = 'GithubOidcExchangeError'
    this.code = code
    this.httpStatus = httpStatus
  }
}

async function parseErrorBody(response: Response): Promise<{ code: string; description: string }> {
  let body: ExchangeErrorBody = {}
  try {
    body = (await response.json()) as ExchangeErrorBody
  } catch {
    // Malformed/empty body — fall back to generic descriptors below.
  }
  return {
    code: body.error ?? `http_${response.status}`,
    description: body.error_description ?? response.statusText,
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Exchanges a GitHub Actions OIDC id_token for a Polaris access token.
 *
 * POSTs `{id_token, account?}` (the `account` key is omitted entirely when
 * absent) to `${polarisUrl}/api/v2/auth/github-oidc` with
 * `Content-Type: application/json` and NO `Authorization` header — the
 * id_token in the body IS the credential.
 *
 * Retry semantics: a 429 or 503 response WITH a `Retry-After` header is
 * retried after waiting the advertised integer delta-seconds, with no
 * retry cap. Any other 4xx — including a 429/503 WITHOUT `Retry-After` —
 * is terminal: throws `GithubOidcExchangeError` immediately, never retries.
 */
export async function exchangeGithubOidc(opts: {
  polarisUrl: string
  idToken: string
  account?: string
  fetchImpl?: typeof fetch
}): Promise<ExchangeSuccess> {
  const fetchImpl = opts.fetchImpl ?? fetch
  const url = `${opts.polarisUrl}/api/v2/auth/github-oidc`
  const body: { id_token: string; account?: string } = { id_token: opts.idToken }
  if (opts.account !== undefined) {
    body.account = opts.account
  }

  for (;;) {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

    if (response.ok) {
      const parsed = (await response.json()) as {
        access_token: string
        token_type: string
        expires_in: number
        account: string
        role: string
      }
      return {
        accessToken: parsed.access_token,
        tokenType: parsed.token_type,
        expiresIn: parsed.expires_in,
        account: parsed.account,
        role: parsed.role,
      }
    }

    const retryAfter = response.headers.get('retry-after')
    if ((response.status === 429 || response.status === 503) && retryAfter !== null) {
      const delaySeconds = Number.parseInt(retryAfter, 10)
      await sleep(delaySeconds * 1000)
      continue
    }

    const { code, description } = await parseErrorBody(response)
    throw new GithubOidcExchangeError(code, description, response.status)
  }
}

// ---------------------------------------------------------------------------
// Action entrypoint
// ---------------------------------------------------------------------------

export async function run(): Promise<void> {
  try {
    const polarisUrl = core.getInput('polaris-url')
    const audienceInput = core.getInput('audience')
    const accountInput = core.getInput('account')
    const exportTfToken = core.getBooleanInput('export-tf-token')
    const maskToken = core.getBooleanInput('mask-token')

    const audience = deriveAudience(polarisUrl, audienceInput)
    const idToken = await core.getIDToken(audience)

    const result = await exchangeGithubOidc({
      polarisUrl,
      idToken,
      account: accountInput === '' ? undefined : accountInput,
    })

    // setSecret MUST run before anything else touches the access token.
    if (maskToken) {
      core.setSecret(result.accessToken)
    }

    core.setOutput('access-token', result.accessToken)
    core.setOutput('expires-in', result.expiresIn)
    core.setOutput('account', result.account)

    if (exportTfToken) {
      const host = canonicalizeAudienceHost(polarisUrl)
      core.exportVariable(tfTokenEnvName(host), result.accessToken)
    }
  } catch (error) {
    // GithubOidcExchangeError's message is already formatted as
    // `code: description` (see its constructor above).
    if (error instanceof Error) {
      core.setFailed(error.message)
    } else {
      core.setFailed(String(error))
    }
  }
}

if (require.main === module) {
  void run()
}
