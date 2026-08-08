// login/src/index.ts
//
// SCAFFOLD STUB — not yet implemented.
//
// This will become the GitHub-OIDC -> Polaris access-token exchange
// described in RFC 030 (§5) "The croonix/polaris-actions repository".
// It is intentionally left as a stub until Shin's failing tests exist
// (workspace TDD rule: spec -> test -> code). Implementing behavior here
// ahead of tests is explicitly out of scope for this task.
//
// Expected shape (per action.yml / RFC 030 §5.3), for reference only:
//   - read inputs: polaris-url (required), audience, account,
//     export-tf-token, mask-token
//   - request + exchange a GitHub Actions OIDC id_token via
//     @actions/core's getIDToken()
//   - POST the id_token to the Polaris instance's OIDC exchange endpoint
//   - mask the minted access token (core.setSecret)
//   - optionally export TF_TOKEN_<host> to $GITHUB_ENV
//   - set outputs: access-token, expires-in, account

function run(): never {
  throw new Error('not implemented')
}

run()
