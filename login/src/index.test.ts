/**
 * @spec-handoff
 * @interface
 *   canonicalizeAudienceHost(raw: string): string
 *   tfTokenEnvName(host: string): string
 *   deriveAudience(polarisUrl: string, explicitAudience?: string): string
 *   exchangeGithubOidc(opts: { polarisUrl: string; idToken: string; account?: string;
 *     fetchImpl?: typeof fetch }): Promise<ExchangeSuccess>
 *   run(): Promise<void>  — entrypoint; guard with `if (require.main === module) { void run() }`
 *     at module bottom, NEVER call unconditionally at module scope (the current stub does this,
 *     which is exactly why every test below currently fails at import time — that must change)
 * @behavior
 *   - tfTokenEnvName: `TF_TOKEN_` + host AS-IS (NO uppercasing) + `.`→`_`, `-`→`__` (R-11 CORRECTED;
 *     rev-2's "uppercase, `.`/`-`→`_`" rule was verified wrong against OpenTofu's own docs)
 *   - canonicalizeAudienceHost: IDENTICAL algorithm to Warden's `CanonicalizeAudience`
 *     (polaris/services/identity/internal/config/config.go) — lowercase, bare host, default port
 *     (443/80) omitted, non-default port retained, IDN as punycode, REJECTS ASCII-only-Punycode
 *     labels (the GO-2026-5026/CVE-2026-39821 class). Vectors below are imported verbatim from
 *     polaris's `audience_punycode_test.go`, not re-derived.
 *   - deriveAudience: explicit non-empty `audience` input wins VERBATIM (no canonicalization — it
 *     may legitimately be the literal fallback string "polaris"); otherwise canonicalize the host
 *     of `polarisUrl`. No static default exists in action.yml by design (D-16).
 *   - exchangeGithubOidc: POST `${polarisUrl}/api/v2/auth/github-oidc`, body `{id_token, account?}`
 *     (`account` key omitted when absent), `Content-Type: application/json`, NO `Authorization`
 *     header. 429/503 WITH `Retry-After`: parse as integer delta-seconds, wait, retry (RFC gives no
 *     retry cap). Any other 4xx (incl. 429/503 WITHOUT `Retry-After` — RFC silent on this combination,
 *     see edge-cases): throw `GithubOidcExchangeError` immediately, never retry.
 *   - run(): `getIDToken(deriveAudience(...))` → `exchangeGithubOidc(...)` → `core.setSecret(token)`
 *     BEFORE any other call touches the token → `setOutput` x3 (`access-token`,`expires-in`,`account`)
 *     → if `export-tf-token !== 'false'`: `exportVariable(tfTokenEnvName(host), token)`. On failure:
 *     `core.setFailed(`code: description`)`, and `run()` resolves normally (never throws out).
 * @edge-cases
 *   - 429/503 WITHOUT `Retry-After`: Shin's filled-in fallback (RFC does not define this combination)
 *     — treated as TERMINAL, no wait, immediate failure. Flagged for Kou/rodo confirmation.
 *   - Host with a non-default port passed to `tfTokenEnvName`: colon is left unmangled (OpenTofu's
 *     docs do not cover ports — documented limitation, not a valid POSIX env-var name, deterministic)
 *   - `mask-token: 'false'` → `core.setSecret` NOT called for the access token (the id_token itself is
 *     still auto-masked inside `core.getIDToken`, outside this action's control)
 *   - `core.getIDToken()` itself rejecting (e.g. missing `id-token: write`) → `run()` catches, calls
 *     `setFailed`, does not throw
 * @see .yui-soul/rfcs/approved/030-github-actions-oidc-wif-login/README.md §4.1, §5.3, D-16, R-11, R2-7
 * @see polaris/services/identity/internal/config/audience_punycode_test.go (imported test vectors)
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as core from '@actions/core'

vi.mock('@actions/core', () => ({
  getInput: vi.fn(),
  getBooleanInput: vi.fn(),
  getIDToken: vi.fn(),
  setSecret: vi.fn(),
  setOutput: vi.fn(),
  exportVariable: vi.fn(),
  setFailed: vi.fn(),
  info: vi.fn(),
}))

// ---------------------------------------------------------------------------
// Section 1: TF_TOKEN_<host> mangling (R-11 CORRECTED rule)
// ---------------------------------------------------------------------------

describe('tfTokenEnvName', () => {
  it('mangles a plain multi-label host with dots only', async () => {
    const { tfTokenEnvName } = await import('./index.js')
    expect(tfTokenEnvName('polaris.croonix.tech')).toBe('TF_TOKEN_polaris_croonix_tech')
  })

  it('mangles a hyphenated host to a DOUBLE underscore, not single (the rev-2 regression case)', async () => {
    const { tfTokenEnvName } = await import('./index.js')
    // This is THE case that broke under rev 2's wrong rule ("uppercase, - -> _") — the dev host
    // is hyphenated, and a single-underscore mangling silently produces the wrong env var name,
    // surfacing as a "no credentials found" failure with no clue why.
    expect(tfTokenEnvName('polaris-dev.croonix.tech')).toBe('TF_TOKEN_polaris__dev_croonix_tech')
  })

  it('mangles a bare single-label host (.localhost) with no leading double-underscore artifact', async () => {
    const { tfTokenEnvName } = await import('./index.js')
    expect(tfTokenEnvName('polaris.localhost')).toBe('TF_TOKEN_polaris_localhost')
  })

  it('does NOT uppercase the host (the exact rev-2 mistake this rule corrects)', async () => {
    const { tfTokenEnvName } = await import('./index.js')
    const result = tfTokenEnvName('polaris.croonix.tech')
    expect(result).not.toBe(result.toUpperCase())
    expect(result).toContain('polaris')
  })

  it('leaves a non-default port unmangled (documented limitation — OpenTofu docs do not cover ports)', async () => {
    const { tfTokenEnvName } = await import('./index.js')
    // Not addressable per RFC 030 R-11: the colon survives verbatim, producing a deterministic but
    // NOT-a-valid-POSIX-env-var-name string. This test pins the CURRENT documented behavior, not a
    // claim that the result is usable — it exists so a future "helpful" fix to strip/reject the port
    // is a deliberate decision, not an accidental behavior change.
    expect(tfTokenEnvName('polaris.example:8443')).toBe('TF_TOKEN_polaris_example:8443')
  })
})

// ---------------------------------------------------------------------------
// Section 2: audience canonicalization — IDENTICAL algorithm to Warden's
// CanonicalizeAudience (D-16). Vectors imported from
// polaris/services/identity/internal/config/audience_punycode_test.go so the
// two independent implementations are checked against the SAME table.
// ---------------------------------------------------------------------------

describe('canonicalizeAudienceHost — accepts (imported from Warden test vectors)', () => {
  it('passes through a plain host unchanged', async () => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    expect(canonicalizeAudienceHost('polaris.example')).toBe('polaris.example')
  })

  it('lowercases a mixed-case host', async () => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    expect(canonicalizeAudienceHost('PoLaRiS.Example')).toBe('polaris.example')
  })

  it('strips a scheme and trailing slash', async () => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    expect(canonicalizeAudienceHost('https://polaris.example/')).toBe('polaris.example')
  })

  it('omits the default https port (443)', async () => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    expect(canonicalizeAudienceHost('polaris.example:443')).toBe('polaris.example')
  })

  it('retains a non-default port (host:port is a genuinely different audience)', async () => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    expect(canonicalizeAudienceHost('polaris.example:8443')).toBe('polaris.example:8443')
  })

  it('preserves a genuine (non-ASCII-only) punycode A-label unchanged', async () => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    // "xn--bcher-kva" decodes to "bücher" — contains real non-ASCII content, so a naive
    // "reject anything starting with xn--" fix would wrongly break this.
    expect(canonicalizeAudienceHost('xn--bcher-kva.example')).toBe('xn--bcher-kva.example')
  })

  it('encodes a raw unicode host to the same punycode A-label', async () => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    expect(canonicalizeAudienceHost('bücher.example')).toBe('xn--bcher-kva.example')
  })
})

describe('canonicalizeAudienceHost — rejects ASCII-only Punycode (CVE-class guard, imported from Warden test vectors)', () => {
  // Each input is a malformed A-label: the "xn--" prefix promises Punycode, but the payload
  // decodes to pure ASCII. Accepting these silently collapses two DISTINCT audience strings onto
  // one canonical value (e.g. "xn--polaris-.example" and "polaris.example" both -> "polaris.example"),
  // which defeats D-16's exact-match anti-replay guarantee. See GO-2026-5026 / CVE-2026-39821 and
  // polaris/services/identity/internal/config/audience_punycode_test.go for the full history.
  it.each([
    ['bare ascii-only punycode label', 'xn--polaris-.example'],
    ['ascii-only punycode label with scheme and trailing slash', 'https://xn--polaris-.example/'],
    ['ascii-only punycode label with explicit non-default port', 'xn--polaris-.example:8443'],
    ['ascii-only punycode in a non-leading label', 'id.xn--warden-.example'],
    ['canonical CVE reproducer', 'xn--example-.com'],
  ])('rejects: %s (%s)', async (_name, raw) => {
    const { canonicalizeAudienceHost } = await import('./index.js')
    expect(() => canonicalizeAudienceHost(raw)).toThrow()
  })
})

// ---------------------------------------------------------------------------
// Section 3: audience derivation (default = host of polaris-url; explicit
// audience input overrides verbatim, no canonicalization)
// ---------------------------------------------------------------------------

describe('deriveAudience', () => {
  it('derives the canonicalized host of polaris-url when no explicit audience is given', async () => {
    const { deriveAudience } = await import('./index.js')
    expect(deriveAudience('https://polaris.croonix.tech', undefined)).toBe('polaris.croonix.tech')
  })

  it('treats an empty-string audience input the same as absent (matches core.getInput() semantics)', async () => {
    const { deriveAudience } = await import('./index.js')
    expect(deriveAudience('https://polaris.croonix.tech', '')).toBe('polaris.croonix.tech')
  })

  it('canonicalizes the derived host (mixed case + trailing slash)', async () => {
    const { deriveAudience } = await import('./index.js')
    expect(deriveAudience('https://PoLaRiS.Croonix.Tech/', undefined)).toBe('polaris.croonix.tech')
  })

  it('uses an explicit audience input VERBATIM, bypassing derivation and canonicalization entirely', async () => {
    const { deriveAudience } = await import('./index.js')
    // "polaris" is the documented global-fallback literal (D-16) — it is not a hostname and must
    // never be run through canonicalizeAudienceHost, which would reject or mangle it.
    expect(deriveAudience('https://polaris.example.com', 'polaris')).toBe('polaris')
  })
})

// ---------------------------------------------------------------------------
// Section 4: exchangeGithubOidc — request contract, success parsing, retry
// semantics, and terminal-failure semantics. Fully hermetic: fetch is a
// locally-injected mock, never the real global.
// ---------------------------------------------------------------------------

describe('exchangeGithubOidc — request contract', () => {
  it('POSTs to <polaris-url>/api/v2/auth/github-oidc', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }),
    )
    await exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 'eyJ.abc.sig', fetchImpl })
    const [url] = fetchImpl.mock.calls[0]
    expect(String(url)).toBe('https://polaris.example.com/api/v2/auth/github-oidc')
  })

  it('sends a JSON body of exactly {id_token} when no account is given', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }),
    )
    await exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 'eyJ.abc.sig', fetchImpl })
    const [, init] = fetchImpl.mock.calls[0]
    expect(JSON.parse(String(init?.body))).toEqual({ id_token: 'eyJ.abc.sig' })
  })

  it('sends a JSON body of exactly {id_token, account} when account is given', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }),
    )
    await exchangeGithubOidc({
      polarisUrl: 'https://polaris.example.com',
      idToken: 'eyJ.abc.sig',
      account: 'croonix',
      fetchImpl,
    })
    const [, init] = fetchImpl.mock.calls[0]
    expect(JSON.parse(String(init?.body))).toEqual({ id_token: 'eyJ.abc.sig', account: 'croonix' })
  })

  it('sends Content-Type: application/json', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }),
    )
    await exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 'eyJ.abc.sig', fetchImpl })
    const [, init] = fetchImpl.mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(headers.get('content-type')).toBe('application/json')
  })

  it('sends NO Authorization header — the id_token in the body IS the credential', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }),
    )
    await exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 'eyJ.abc.sig', fetchImpl })
    const [, init] = fetchImpl.mock.calls[0]
    const headers = new Headers(init?.headers)
    expect(headers.has('authorization')).toBe(false)
  })

  it('never puts the id_token in the URL/query string', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }),
    )
    await exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 'eyJ.abc.sig', fetchImpl })
    const [url] = fetchImpl.mock.calls[0]
    expect(String(url)).not.toContain('eyJ.abc.sig')
  })
})

describe('exchangeGithubOidc — success response parsing', () => {
  it('resolves with all five response fields on 200', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'minted-token-abc',
          token_type: 'Bearer',
          expires_in: 900,
          account: 'croonix',
          role: 'user',
        }),
        { status: 200, headers: jsonHeaders() },
      ),
    )
    const result = await exchangeGithubOidc({
      polarisUrl: 'https://polaris.example.com',
      idToken: 'eyJ.abc.sig',
      fetchImpl,
    })
    expect(result).toEqual({
      accessToken: 'minted-token-abc',
      tokenType: 'Bearer',
      expiresIn: 900,
      account: 'croonix',
      role: 'user',
    })
  })
})

describe('exchangeGithubOidc — retry semantics', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('honours Retry-After on 429, parsed as integer delta-seconds, and retries to success', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(errorResponse(429, 'rate_limited', 'too many requests', { 'Retry-After': '5' }))
      .mockResolvedValueOnce(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }))

    const promise = exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl })
    await vi.advanceTimersByTimeAsync(5_000)
    await expect(promise).resolves.toMatchObject({ accessToken: successBody().access_token })
    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })

  it('does not retry a 429 before the advertised Retry-After delay has elapsed', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(errorResponse(429, 'rate_limited', 'too many requests', { 'Retry-After': '5' }))
      .mockResolvedValueOnce(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }))

    const promise = exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl })
    await vi.advanceTimersByTimeAsync(4_999)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    await promise
    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })

  it('honours Retry-After on 503 and retries to success (distinguishes "GitHub was down" from a deny)', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        errorResponse(503, 'provider_unavailable', 'jwks unreachable', { 'Retry-After': '300' }),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }))

    const promise = exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl })
    await vi.advanceTimersByTimeAsync(300_000)
    await expect(promise).resolves.toMatchObject({ accessToken: successBody().access_token })
    expect(fetchImpl).toHaveBeenCalledTimes(2)
  })

  it('retries more than once across consecutive retryable responses (a bounded loop, not a single retry)', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(errorResponse(503, 'provider_unavailable', 'jwks unreachable', { 'Retry-After': '1' }))
      .mockResolvedValueOnce(errorResponse(503, 'provider_unavailable', 'jwks unreachable', { 'Retry-After': '1' }))
      .mockResolvedValueOnce(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() }))

    const promise = exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl })
    await vi.advanceTimersByTimeAsync(1_000)
    await vi.advanceTimersByTimeAsync(1_000)
    await expect(promise).resolves.toMatchObject({ accessToken: successBody().access_token })
    expect(fetchImpl).toHaveBeenCalledTimes(3)
  })

  it('fails immediately (no wait, no retry) on 429/503 WITHOUT a Retry-After header', async () => {
    const { exchangeGithubOidc, GithubOidcExchangeError } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(errorResponse(503, 'provider_unavailable', 'jwks unreachable'))

    await expect(
      exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl }),
    ).rejects.toThrow(GithubOidcExchangeError)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  it('does not retry any 4xx other than 429 (403 untrusted_repository is terminal)', async () => {
    const { exchangeGithubOidc, GithubOidcExchangeError } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(errorResponse(403, 'untrusted_repository', 'no matching binding for this repository'))

    await expect(
      exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl }),
    ).rejects.toThrow(GithubOidcExchangeError)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  it('surfaces the server error code on a terminal failure (403 untrusted_repository)', async () => {
    const { exchangeGithubOidc } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(errorResponse(403, 'untrusted_repository', 'no matching binding for this repository'))

    await expect(
      exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl }),
    ).rejects.toMatchObject({ code: 'untrusted_repository', httpStatus: 403 })
  })

  it('does not retry a 400 invalid_request', async () => {
    const { exchangeGithubOidc, GithubOidcExchangeError } = await import('./index.js')
    const fetchImpl = vi.fn().mockResolvedValue(errorResponse(400, 'invalid_request', 'malformed body'))

    await expect(
      exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl }),
    ).rejects.toThrow(GithubOidcExchangeError)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  it('does not retry a 401 audience_mismatch', async () => {
    const { exchangeGithubOidc, GithubOidcExchangeError } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(errorResponse(401, 'audience_mismatch', 'id_token audience does not match this instance'))

    await expect(
      exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl }),
    ).rejects.toThrow(GithubOidcExchangeError)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  it('does not retry a 409 ambiguous_account', async () => {
    const { exchangeGithubOidc, GithubOidcExchangeError } = await import('./index.js')
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(errorResponse(409, 'ambiguous_account', 'repo trusted in multiple accounts'))

    await expect(
      exchangeGithubOidc({ polarisUrl: 'https://polaris.example.com', idToken: 't', fetchImpl }),
    ).rejects.toThrow(GithubOidcExchangeError)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// Section 5: run() orchestration — inputs, getIDToken call, masking order,
// outputs, TF_TOKEN_ export, and error surfacing.
// ---------------------------------------------------------------------------

describe('run — orchestration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(core.getBooleanInput).mockImplementation((name: string) => {
      if (name === 'export-tf-token' || name === 'mask-token') return true
      return false
    })
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function stubInputs(overrides: Record<string, string> = {}) {
    const values: Record<string, string> = {
      'polaris-url': 'https://polaris.croonix.tech',
      audience: '',
      account: '',
      ...overrides,
    }
    vi.mocked(core.getInput).mockImplementation((name: string) => values[name] ?? '')
  }

  it('calls core.getIDToken with the derived audience (default: canonicalized polaris-url host)', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() })),
    )
    const { run } = await import('./index.js')
    await run()
    expect(core.getIDToken).toHaveBeenCalledWith('polaris.croonix.tech')
  })

  it('calls core.getIDToken with an explicit audience input, verbatim, when provided', async () => {
    stubInputs({ audience: 'polaris' })
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() })),
    )
    const { run } = await import('./index.js')
    await run()
    expect(core.getIDToken).toHaveBeenCalledWith('polaris')
  })

  it('calls core.setSecret on the minted access token BEFORE any output or export touches it', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() })),
    )

    const callOrder: string[] = []
    vi.mocked(core.setSecret).mockImplementation(() => {
      callOrder.push('setSecret')
    })
    vi.mocked(core.setOutput).mockImplementation(() => {
      callOrder.push('setOutput')
    })
    vi.mocked(core.exportVariable).mockImplementation(() => {
      callOrder.push('exportVariable')
    })

    const { run } = await import('./index.js')
    await run()

    expect(callOrder[0]).toBe('setSecret')
    expect(callOrder).toContain('setOutput')
    expect(callOrder).toContain('exportVariable')
  })

  it('sets exactly three outputs: access-token, expires-in, account', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() })),
    )
    const { run } = await import('./index.js')
    await run()

    expect(core.setOutput).toHaveBeenCalledTimes(3)
    expect(core.setOutput).toHaveBeenCalledWith('access-token', successBody().access_token)
    expect(core.setOutput).toHaveBeenCalledWith('expires-in', successBody().expires_in)
    expect(core.setOutput).toHaveBeenCalledWith('account', successBody().account)
  })

  it('exports TF_TOKEN_<host> when export-tf-token defaults true', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() })),
    )
    const { run } = await import('./index.js')
    await run()

    expect(core.exportVariable).toHaveBeenCalledWith('TF_TOKEN_polaris_croonix_tech', successBody().access_token)
  })

  it('does NOT export TF_TOKEN_<host> when export-tf-token is set to false', async () => {
    stubInputs()
    vi.mocked(core.getBooleanInput).mockImplementation((name: string) => {
      if (name === 'export-tf-token') return false
      if (name === 'mask-token') return true
      return false
    })
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() })),
    )
    const { run } = await import('./index.js')
    await run()

    expect(core.exportVariable).not.toHaveBeenCalled()
  })

  it('does NOT call core.setSecret when mask-token is set to false', async () => {
    stubInputs()
    vi.mocked(core.getBooleanInput).mockImplementation((name: string) => {
      if (name === 'mask-token') return false
      if (name === 'export-tf-token') return true
      return false
    })
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify(successBody()), { status: 200, headers: jsonHeaders() })),
    )
    const { run } = await import('./index.js')
    await run()

    expect(core.setSecret).not.toHaveBeenCalled()
  })

  it('calls core.setFailed with a message that includes the server error code on a terminal failure', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(errorResponse(403, 'untrusted_repository', 'no matching binding')),
    )
    const { run } = await import('./index.js')
    await run()

    expect(core.setFailed).toHaveBeenCalledTimes(1)
    const [message] = vi.mocked(core.setFailed).mock.calls[0]
    expect(String(message)).toContain('untrusted_repository')
  })

  it('resolves normally (does not throw) even when the exchange terminally fails', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(errorResponse(403, 'untrusted_repository', 'no matching binding')),
    )
    const { run } = await import('./index.js')
    await expect(run()).resolves.not.toThrow()
  })

  it('does not call setOutput/setSecret/exportVariable when the exchange terminally fails', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockResolvedValue('the-oidc-id-token')
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(errorResponse(403, 'untrusted_repository', 'no matching binding')),
    )
    const { run } = await import('./index.js')
    await run()

    expect(core.setOutput).not.toHaveBeenCalled()
    expect(core.setSecret).not.toHaveBeenCalled()
    expect(core.exportVariable).not.toHaveBeenCalled()
  })

  it('calls setFailed, not throw, when core.getIDToken itself rejects (e.g. missing id-token: write permission)', async () => {
    stubInputs()
    vi.mocked(core.getIDToken).mockRejectedValue(new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN'))
    const { run } = await import('./index.js')
    await expect(run()).resolves.not.toThrow()
    expect(core.setFailed).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function successBody() {
  return {
    access_token: 'minted-token-abc',
    token_type: 'Bearer',
    expires_in: 900,
    account: 'croonix',
    role: 'user',
  }
}

function jsonHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return { 'Content-Type': 'application/json', ...extra }
}

function errorResponse(
  status: number,
  error: string,
  errorDescription: string,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify({ error, error_description: errorDescription }), {
    status,
    headers: jsonHeaders(extraHeaders),
  })
}
