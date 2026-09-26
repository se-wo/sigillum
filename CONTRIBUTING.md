# Contributing to sigillum

**Security issues:** do not open a public issue or PR. Follow
[SECURITY.md](SECURITY.md) and report privately.

## Development workflow

You need Go (see the `go` / `toolchain` lines in [`go.mod`](go.mod)) and
`make`. The Makefile installs its own tools (controller-gen, setup-envtest,
govulncheck) into `bin/` at pinned versions.

```sh
make build              # compile bin/sigillum
make vet                # go vet ./...
make test-unit          # fast unit tests (go test -short)
make test               # regenerates manifests/deepcopy, then unit + envtest suite
make vulncheck          # govulncheck
```

- After changing API types or kubebuilder markers, run
  `make manifests generate` and commit the regenerated files.
- `go mod tidy` must leave `go.mod` and `go.sum` unchanged; CI fails
  otherwise.
- `make test` also renders the Helm chart (`test/chart`, `test/examples`)
  when `helm` is on `PATH`; those tests are skipped otherwise.
- `make e2e` runs the kind + Mailpit end-to-end suite. It needs Docker and a
  kind cluster; CI runs it on every PR, so running it locally is optional.

## Pull requests

- All changes to `main` go through a pull request; direct pushes and force
  pushes are blocked.
- These checks must pass before a PR can be merged: `build-test`, `e2e`,
  `govulncheck`, `dependency-review`, `analyze (go)` and `analyze (actions)`.
  CodeQL results are also enforced: alerts of high or critical security
  severity, or of error severity, block the merge.
- CI does not start automatically for PRs from outside contributors; a
  maintainer has to approve the workflow run first. Please be patient.
- Keep PRs focused, add or update tests for behaviour changes, and update
  the docs (README, `docs/SPEC.md`, chart values) when user-facing behaviour
  changes.
- Record user-facing changes in [`CHANGELOG.md`](CHANGELOG.md) under the
  version being prepared (its heading says `unreleased` until the release).

## Releases

1. In a PR, bump `VERSION` in the `Makefile` and `version` / `appVersion`
   in `charts/sigillum/Chart.yaml`, and replace `unreleased` in the
   version's `CHANGELOG.md` heading with the release date.
2. After it is merged, push the tag `v<version>` on that commit of `main`.
   [`release.yml`](.github/workflows/release.yml) publishes and signs the
   image and chart, then creates the GitHub Release with that version's
   `CHANGELOG.md` section as notes (`hack/release-notes.sh`).

## GitHub Actions

- Every action must be pinned to a full commit SHA, with the release tag as
  a trailing comment (`uses: actions/checkout@<sha> # v7.0.1`). The
  repository enforces SHA pinning.
- Only GitHub-owned actions and `helm/kind-action` are allowed by the
  repository's Actions policy; workflows that use anything else will fail.
- Keep workflow `permissions:` minimal and pass untrusted values to `run:`
  steps through `env:` rather than `${{ }}` expressions.

## Dependencies

Go modules, Actions and Docker base images are updated by Dependabot
(see [`.github/dependabot.yml`](.github/dependabot.yml)).
