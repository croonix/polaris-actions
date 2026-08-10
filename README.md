# croonix/polaris-actions

**This is `croonix/polaris-actions`.** It is **not** `croonix/int-polaris-actions`
(the pre-existing, private, general-purpose Croonix Actions hub for internal
Azure/OpenTofu pipelines) and it is **not** `croonix/polaris-actions-e2e` (a
private, throwaway, `workflow_dispatch`-only smoke-test harness that exercises
this repo's `login` action against a dev Polaris instance — it holds no
product code of its own).

| | `croonix/polaris-actions` (this repo) | `croonix/int-polaris-actions` | `croonix/polaris-actions-e2e` |
|---|---|---|---|
| Role | Polaris-product-specific login action | General-purpose internal Actions hub | Smoke-test harness for this repo |
| Visibility | **Public** | Private | Private |
| Consumed by | Any repo, any org, pinned by commit SHA | Croonix-internal repos only | Nobody — it's a test fixture |
| Versioning | Semver + SHA-pinned (`v1` convenience tag, see below) | `@latest` moving tag | N/A |

These three repos have similar names and it is easy to `uses:` the wrong one.
If you are here to authenticate a Terraform/OpenTofu-against-Polaris workflow,
you are in the right place.

## What this is

A GitHub Action that authenticates to a [Polaris](https://github.com/croonix/polaris)
instance using GitHub Actions OIDC (workload identity federation) — no static,
long-lived credential stored as a repo secret. It exchanges the workflow run's
GitHub-issued `id_token` for a short-lived Polaris access token, and optionally
exports `TF_TOKEN_<host>` so Terraform/OpenTofu's native `cloud`/`remote` backend
picks it up automatically.

## Usage

**Always pin by commit SHA, never by a floating tag like `@v1`, in your own
audit trail.** The `v1` tag is a convenience alias that moves forward on
every `v1.x.y` release, so it always points at the latest patch — handy for
browsing the repo, but it means the code that actually runs in your pipeline
can change without a corresponding change in your own workflow file. Pinning
by SHA makes the contract explicit: what you see in your diff is exactly what
runs. Use the `# vX.Y.Z` comment purely as a human-readable label next to the
pinned SHA.

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
        # Real pin: a 40-char commit SHA + version comment. Never copy `@<sha>` literally.
        uses: croonix/polaris-actions/login@<sha>   # v1.0.0
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
        uses: croonix/polaris-actions/login@<sha>   # v1.0.0
        with:
          polaris-url: https://polaris.example.com

      - uses: hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e # v4.0.1
      - run: terraform init && terraform apply -auto-approve   # TF_TOKEN_* already exported
```

The `permissions:` block above is scoped at the **job** level (not the
workflow level), which is the correct least-privilege posture — declaring
`contents: read` explicitly turns the block into an allowlist, so any
permission not listed is implicitly denied.

## Inputs / outputs

See [`login/action.yml`](login/action.yml) for the full, current contract.
Input and output names are part of this action's public contract: once
external workflows pin to a released version, renaming or removing an input
or output is a breaking change for them. For that reason, names are reviewed
carefully before each release — especially before `v1.0.0`.

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

## Standing obligations

- **Runtime deprecation**: this action currently targets `node24`
  (`runs.using` in `login/action.yml`). Dependabot does not surface `runs.using`
  migrations — bumping to the next Actions runtime when `node24` is deprecated
  is a manually-tracked obligation, not automated.
- **SHA pinning**: every third-party `uses:` in this repo's own workflows is
  pinned to a commit SHA with a `# vX.Y.Z` version comment. No floating tags.

## License

Apache-2.0 — see [LICENSE](LICENSE).
