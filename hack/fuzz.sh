#!/usr/bin/env bash
# Run the native Go fuzz targets (func FuzzXxx(f *testing.F) in *_test.go).
# `go test -fuzz` takes one package and one target at a time, so this loops
# over them and reports every failing target at the end, not just the first.
#
#   hack/fuzz.sh list                    # "<package dir> <FuzzName>" per line
#   hack/fuzz.sh run <fuzztime> [dir...] # fuzz each target for <fuzztime>
#
# A failing input is written to <dir>/testdata/fuzz/<FuzzName>/ and from then
# on replays with every plain `go test`. Commit it together with the fix.
set -euo pipefail

cd "$(dirname "$0")/.."

list() {
  # Test files with build constraints (envtest, e2e) hold no fuzz targets.
  grep -rE --include='*_test.go' -o '^func Fuzz[A-Za-z0-9_]*\(' "${@:-.}" |
    sed -E 's|^(\./)?(.*)/[^/]+_test\.go:func (Fuzz[A-Za-z0-9_]*)\($|\2 \3|' |
    sort -u
}

case "${1:-}" in
list)
  shift
  list "$@"
  ;;
run)
  fuzztime=${2:?usage: $0 run <fuzztime> [dir...]}
  shift 2
  failed=()
  while read -r dir name; do
    echo "::group::$dir $name ($fuzztime)"
    if ! go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" "./$dir"; then
      failed+=("$dir $name")
    fi
    echo "::endgroup::"
  done < <(list "$@")
  if ((${#failed[@]})); then
    printf 'fuzz target failed: %s\n' "${failed[@]}" >&2
    echo "failing inputs are in <package>/testdata/fuzz/<target>/" >&2
    exit 1
  fi
  ;;
*)
  echo "usage: $0 list [dir...] | run <fuzztime> [dir...]" >&2
  exit 2
  ;;
esac
