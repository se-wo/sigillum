# Contributing to sigillum

**Security issues:** do not open a public issue or PR. Follow
[SECURITY.md](SECURITY.md) and report privately.

## Development workflow

You need Go (see the `go` / `toolchain` lines in [`go.mod`](go.mod)) and
`make`. The Makefile installs its own tools (controller-gen, setup-envtest,
govulncheck, actionlint) into `bin/` at pinned versions.

```sh
make build              # compile bin/sigillum
make vet                # go vet ./...
make test-unit          # fast unit tests (go test -short)
make test               # regenerates manifests/deepcopy, then unit + envtest suite
make vulncheck          # govulncheck
make fuzz               # every fuzz target for 30s (FUZZTIME=5m, FUZZ_PKGS=internal/policy)
make lint-actions       # actionlint + zizmor on .github/ (needs zizmor, see below)
```

- After changing API types or kubebuilder markers, run
  `make manifests generate` and commit the regenerated files.
- `go mod tidy` must leave `go.mod` and `go.sum` unchanged; CI fails
  otherwise.
- `make test` also renders the Helm chart (`test/chart`, `test/examples`)
  when `helm` is on `PATH`; those tests are skipped otherwise.
- Code that parses untrusted input (SMTP DATA, REST requests, addresses,
  credential strings) should have a native Go fuzz target
  (`func FuzzXxx(f *testing.F)` in the package's `fuzz_test.go`) that
  checks a property, not only that nothing panics. `go test` replays its
  seeds, and the [`fuzz`](.github/workflows/fuzz.yml) workflow fuzzes every
  target on PRs and daily. When a fuzzer finds a failing input, commit the
  file it writes to `testdata/fuzz/<FuzzName>/` together with the fix, so
  it stays a regression test.
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

### Size of a pull request

A pull request should be reviewable in one sitting, by a person and by an
automated review. Large ones get skimmed, and their findings arrive after the
merge.

- **One concern per pull request.** A feature, a fix or a refactor, not
  several. A refactor that a feature needs goes first, in its own pull
  request, without behaviour changes.
- **Aim for under 400 changed lines of hand-written, non-test code.** Tests,
  generated files and recipes come on top. Above that, split it or explain in
  the description why it cannot be split.
- **Generated files in their own commit** (`make manifests generate`), so
  the hand-written commits can be read alone. `.gitattributes` marks them as
  generated, and GitHub collapses them in the diff.
- **`main` stays releasable after every merge.** A new backend type,
  `authType` or CRD field is accepted by the webhook only from the pull request
  that makes it work. Unfinished code may be merged as long as nothing can
  reach it.
- **The roadmap lists the pull requests of a release** in order, with their
  dependencies ([`docs/SPEC.md`](docs/SPEC.md#8-roadmap) §8). Open one per
  row; when a row turns out too big, split it there first.
- **Stacked pull requests** are fine when one row needs the previous one:
  base the second on the first one's branch and retarget it to `main` after
  the first is merged.
- Review findings are fixed in the same pull request before it is merged,
  not in a follow-up.

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
- The [`lint-actions`](.github/workflows/lint-actions.yml) workflow runs
  [actionlint](https://github.com/rhysd/actionlint) (with shellcheck for
  `run:` scripts) and [zizmor](https://docs.zizmor.sh/) on every PR. Run
  them locally with `make lint-actions` after installing zizmor
  (`pip install --require-hashes -r .github/zizmor/requirements.txt`) and,
  for the checks of `run:` scripts, shellcheck. A zizmor
  finding that does not apply is ignored on the flagged line with
  `# zizmor: ignore[<audit>]` and a comment explaining why; rules that do
  not fit the repository are disabled in
  [`.github/zizmor.yml`](.github/zizmor.yml).

## Dependencies

Go modules, Actions and Docker base images are updated by Dependabot
(see [`.github/dependabot.yml`](.github/dependabot.yml)).
