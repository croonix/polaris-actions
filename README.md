# croonix/polaris-actions

A GitHub Action that authenticates to a [Polaris](https://github.com/croonix/polaris)
instance using GitHub Actions OIDC (workload identity federation) — no static,
long-lived credential stored as a repo secret. It exchanges the workflow run's
GitHub-issued `id_token` for a short-lived Polaris access token, and optionally
exports `TF_TOKEN_<host>` so Terraform/OpenTofu's native `cloud`/`remote` backend
picks it up automatically.

- No static credentials — authentication is short-lived and per-run
- Works with both OpenTofu and HashiCorp Terraform
- Optional automatic `TF_TOKEN_<host>` export for zero-config backend auth
- Token is registered as a masked secret by default

> **Note:** if you found this repo by searching for "polaris-actions," there are
> two other, similarly-named Croonix repos that are **not** this one:
> `croonix/int-polaris-actions` (a private, general-purpose internal Actions
> hub, unrelated to this product) and `croonix/polaris-actions-e2e` (a private
> test harness used internally to validate this action end-to-end). Neither is
> public; if you can see this README, you're already in the right repo.

## Usage

**Always pin by commit SHA, never by a floating tag like `@v1`, in your own
audit trail** — the `v1` tag documented below is a convenience alias that
moves forward on every `v1.x.y` release. The SHA is the actual contract; the
tag is just a human-friendly pointer to it.

### With OpenTofu

```yaml
name: Infra
on:
  push:
    branches: [main]

jobs:
  apply:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write            # REQUIRED — without it, no id_token is issued
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Authenticate to Polaris
        uses: croonix/polaris-actions/login@7cf5fb442f196edb78591a404828619bce6811a7 # v1.0.1
        with:
          polaris-url: https://polaris.example.com

      - uses: opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4 # v2.0.2
      - run: tofu init && tofu apply -auto-approve   # TF_TOKEN_* already exported
```

### With HashiCorp Terraform

```yaml
name: Infra
on:
  push:
    branches: [main]

jobs:
  apply:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write            # REQUIRED — without it, no id_token is issued
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Authenticate to Polaris
        uses: croonix/polaris-actions/login@7cf5fb442f196edb78591a404828619bce6811a7 # v1.0.1
        with:
          polaris-url: https://polaris.example.com

      - uses: hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e # v4.0.1
      - run: terraform init && terraform apply -auto-approve   # TF_TOKEN_* already exported
```

The `permissions:` block above is scoped at the **job** level (not the
workflow level), which is the correct least-privilege posture — declaring
`contents: read` explicitly turns the block into an allowlist, so any
permission not listed is implicitly denied.

## Inputs

| Input | Description | Required | Default |
|---|---|---|---|
| `polaris-url` | Base URL of the Polaris instance (e.g. `https://polaris.example.com`). | Yes | — |
| `audience` | OIDC audience to request. Must match the Polaris instance's expectation. If unset, defaults at runtime to the host of `polaris-url` (per-instance audience). Set explicitly to `"polaris"` only for instances using the documented global fallback audience. | No | *(derived from `polaris-url`'s host at runtime)* |
| `account` | Polaris account slug. Required only if the repo is trusted in more than one account. | No | — |
| `export-tf-token` | Export `TF_TOKEN_<host>` to `$GITHUB_ENV` for subsequent tofu/terraform steps. | No | `true` |
| `mask-token` | Register the minted token as a secret so it is masked in logs. Keep `true` unless you have a specific reason not to. | No | `true` |

## Outputs

| Output | Description |
|---|---|
| `access-token` | The minted Polaris access token. Masked. Prefer `export-tf-token` over consuming this directly. |
| `expires-in` | Token lifetime, in seconds. |
| `account` | The Polaris account slug the token is scoped to. |

Input and output names are a public contract once this action is pinned by
consumers — they don't change casually across releases.

## Development

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm run lint    # tsc --noEmit
pnpm run build   # ncc bundle -> login/dist/index.js (COMMITTED — required for JS actions)
pnpm run test
```

`login/dist/index.js` is a committed, bundled artifact — GitHub Actions runs it
directly with no build step on the consumer's side. CI enforces that the
committed bundle matches a fresh rebuild (dist-freshness check).

This action currently targets the `node24` Actions runtime. When that runtime
is deprecated, a bump will ship as a new release.

## License

Apache-2.0 — see [LICENSE](LICENSE).
