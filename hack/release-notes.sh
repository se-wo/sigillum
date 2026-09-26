#!/usr/bin/env bash
# Print the CHANGELOG.md section of one version, without its heading, for
# use as GitHub Release notes. A pre-release (0.3.0-rc.1) without its own
# section uses the section of its final version (0.3.0).
#
#   hack/release-notes.sh 0.3.0 [CHANGELOG.md]
set -euo pipefail

version=${1:?usage: $0 <version> [changelog]}
changelog=${2:-$(dirname "$0")/../CHANGELOG.md}

section() {
  # From "## [<v>]" up to the next "## [" heading or the link definitions.
  awk -v v="$1" '
    index($0, "## [" v "]") == 1 { on = 1; next }
    on && (/^## \[/ || /^\[[^]]+\]: /) { exit }
    on { print }
  ' "$changelog" | sed -e '/./,$!d' # drop leading blank lines
}

# Command substitution also drops trailing blank lines.
notes=$(section "$version")
if [[ -z "$notes" && "$version" == *-* ]]; then
  notes=$(section "${version%%-*}")
fi
if [[ -z "$notes" ]]; then
  echo "error: no non-empty section for $version in $changelog" >&2
  exit 1
fi
printf '%s\n' "$notes"
