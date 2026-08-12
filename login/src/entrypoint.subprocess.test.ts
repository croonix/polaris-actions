/**
 * @spec-handoff
 * @interface (module-scope side effect) `if (require.main === module) { void run() }`
 *   at the bottom of login/src/index.ts
 * @behavior
 *   - When the COMPILED BUNDLE (login/dist/index.js) is executed directly as a
 *     subprocess via `node dist/index.js` (the exact way the GitHub Actions
 *     runner invokes a JavaScript action), the entrypoint guard MUST evaluate
 *     truthy and `run()` MUST actually execute — producing its real side
 *     effects: an HTTP POST to `${polaris-url}/api/v2/auth/github-oidc`, and a
 *     `GITHUB_OUTPUT` file write containing `access-token`/`expires-in`/`account`.
 *   - This is DISTINCT from calling `run()` via `import('./index.js')` in-process
 *     (see index.test.ts) — that path never exercises the guard at all, since
 *     the guard is bypassed by direct invocation. Only a real subprocess spawn
 *     of the compiled dist/ bundle can prove the guard fires in production.
 * @edge-cases
 *   - Bug under test (reported by Sui): in the ncc/webpack ESM bundle output,
 *     the `hmd()` harmony module decorator reassigns `module` to a NEW object
 *     (`Object.create(module)`) whose reference is never identical to the
 *     cached module object, so `require.main === module` (transpiled by ncc to
 *     `__nccwpck_require__.c[__nccwpck_require__.s] === module`) is always
 *     false in the compiled bundle — `run()` never invoked, action is a
 *     complete no-op, exit code 0, zero output, zero HTTP calls.
 * @see login/src/index.ts:258
 */

import { readFileSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

const DIST_PATH = fileURLToPath(new URL('../dist/index.js', import.meta.url))

// ---------------------------------------------------------------------------
// Local HTTP fixture simulating BOTH the GitHub Actions OIDC token-request
// endpoint (ACTIONS_ID_TOKEN_REQUEST_URL) and the Polaris github-oidc
// exchange endpoint — a real listening server, not a mock of `fetch`.
// ---------------------------------------------------------------------------

interface RecordedRequest {
  method: string | undefined
  url: string | undefined
  body: string
}

function startFixtureServer(): Promise<{
  server: Server
  port: number
  requests: RecordedRequest[]
}> {
  const requests: RecordedRequest[] = []
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
    })
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, body })

      if (req.url?.startsWith('/oidc-token')) {
        // Shape expected by @actions/core's OidcClient.getCall(): { value }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ value: 'fake-github-oidc-id-token' }))
        return
      }

      if (req.url === '/api/v2/auth/github-oidc') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(
          JSON.stringify({
            access_token: 'fake-polaris-access-token',
            token_type: 'Bearer',
            expires_in: 3600,
            account: 'croonix-test-account',
            role: 'reader',
          }),
        )
        return
      }

      res.writeHead(404)
      res.end()
    })
  })

  return new Promise((resolve, reject) => {
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        reject(new Error('fixture server did not bind to a port'))
        return
      }
      resolve({ server, port: address.port, requests })
    })
  })
}

function stopFixtureServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()))
}

// ---------------------------------------------------------------------------
// Spawns `node dist/index.js` as a REAL child process — the same invocation
// the GitHub Actions runner performs for a `runs: { using: 'node24' }`
// JavaScript action. Env vars follow the exact `INPUT_<NAME>` / runner
// convention @actions/core itself reads (see @actions/core's core.js
// getInput and oidc-utils.js getIDTokenUrl/getRequestToken).
// ---------------------------------------------------------------------------

function runDistAsSubprocess(env: Record<string, string>): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [DIST_PATH], {
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString()
    })

    child.on('error', reject)
    child.on('close', (exitCode) => {
      resolve({ exitCode, stdout, stderr })
    })
  })
}

describe('login/dist/index.js entrypoint guard — real subprocess invocation', () => {
  let fixture: { server: Server; port: number; requests: RecordedRequest[] }
  let githubOutputPath: string

  beforeEach(async () => {
    fixture = await startFixtureServer()
    githubOutputPath = join(tmpdir(), `github-output-${process.pid}-${Date.now()}.txt`)
    writeFileSync(githubOutputPath, '')
  })

  afterEach(async () => {
    await stopFixtureServer(fixture.server)
  })

  it('actually invokes run() when the compiled bundle is executed directly — makes the expected Polaris exchange HTTP call', async () => {
    const polarisUrl = `http://127.0.0.1:${fixture.port}`

    const { exitCode } = await runDistAsSubprocess({
      'INPUT_POLARIS-URL': polarisUrl,
      INPUT_AUDIENCE: 'polaris',
      INPUT_ACCOUNT: '',
      'INPUT_EXPORT-TF-TOKEN': 'false',
      'INPUT_MASK-TOKEN': 'false',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fake-request-token',
      ACTIONS_ID_TOKEN_REQUEST_URL: `http://127.0.0.1:${fixture.port}/oidc-token?`,
      GITHUB_OUTPUT: githubOutputPath,
    })

    expect(exitCode).toBe(0)

    // The bug under test: run() never fires, so NEITHER the OIDC token
    // endpoint NOR the Polaris exchange endpoint ever gets a request. A
    // no-op process exits 0 having made zero HTTP calls — indistinguishable
    // from "everything worked" by exit code alone, which is exactly why
    // Sui's report singles out that exit-code-0 is not sufficient evidence.
    const exchangeRequest = fixture.requests.find((r) => r.url === '/api/v2/auth/github-oidc')
    expect(exchangeRequest).toBeDefined()
  })

  it('actually invokes run() when the compiled bundle is executed directly — writes access-token/expires-in/account to GITHUB_OUTPUT', async () => {
    const polarisUrl = `http://127.0.0.1:${fixture.port}`

    const { exitCode } = await runDistAsSubprocess({
      'INPUT_POLARIS-URL': polarisUrl,
      INPUT_AUDIENCE: 'polaris',
      INPUT_ACCOUNT: '',
      'INPUT_EXPORT-TF-TOKEN': 'false',
      'INPUT_MASK-TOKEN': 'false',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fake-request-token',
      ACTIONS_ID_TOKEN_REQUEST_URL: `http://127.0.0.1:${fixture.port}/oidc-token?`,
      GITHUB_OUTPUT: githubOutputPath,
    })

    expect(exitCode).toBe(0)

    const outputContents = readFileSync(githubOutputPath, 'utf8')
    // core.setOutput's file-command format is `name<<delimiter\nvalue\ndelimiter`.
    // We assert on substance (the keys and minted values are present), not the
    // exact delimiter, since the delimiter itself is a random UUID per call.
    expect(outputContents).toContain('access-token')
    expect(outputContents).toContain('fake-polaris-access-token')
    expect(outputContents).toContain('account')
    expect(outputContents).toContain('croonix-test-account')
  })
})
