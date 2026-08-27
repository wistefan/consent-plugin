#!/usr/bin/env bash
#
# Verifies (or adds) the Apache-2.0 copyright header on every Go source file.
#
#   hack/license-header.sh check   # default; exits 1 and lists files that lack it
#   hack/license-header.sh fix     # prepends the header where it is missing
#
# The header text lives in hack/license-header.txt so this script, the `make`
# targets and CI all share one source of truth - editing the header in one place
# is enough.
#
# Only *.go files are checked: the header is a /* */ block, which is not valid
# comment syntax in the Dockerfile or the Makefile.
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly HEADER_FILE="${REPO_ROOT}/hack/license-header.txt"
readonly MODE="${1:-check}"

if [[ ! -f "${HEADER_FILE}" ]]; then
  echo "error: header template not found at ${HEADER_FILE}" >&2
  exit 2
fi

readonly HEADER_LINES="$(wc -l < "${HEADER_FILE}" | tr -d '[:space:]')"

# All Go sources, excluding vendored and generated trees.
collect_files() {
  find "${REPO_ROOT}" \
    -type d \( -name vendor -o -name .git -o -name node_modules \) -prune -o \
    -type f -name '*.go' -print | sort
}

# True when the file already starts with the exact header.
has_header() {
  local file="$1"
  diff -q <(head -n "${HEADER_LINES}" "${file}") "${HEADER_FILE}" >/dev/null 2>&1
}

# Prepends the header plus a blank line. The blank line matters: without it the
# license block would become the package's doc comment (`go doc` would print the
# licence instead of the package documentation).
add_header() {
  local file="$1" tmp
  tmp="$(mktemp)"
  cat "${HEADER_FILE}" > "${tmp}"
  printf '\n' >> "${tmp}"
  cat "${file}" >> "${tmp}"
  mv "${tmp}" "${file}"
}

missing=()
while IFS= read -r file; do
  has_header "${file}" || missing+=("${file}")
done < <(collect_files)

case "${MODE}" in
  check)
    if (( ${#missing[@]} > 0 )); then
      echo "The Apache-2.0 copyright header is missing from ${#missing[@]} file(s):" >&2
      for file in "${missing[@]}"; do
        echo "  ${file#"${REPO_ROOT}"/}" >&2
      done
      echo >&2
      echo "Run 'make license-fix' (or hack/license-header.sh fix) to add it." >&2
      exit 1
    fi
    echo "copyright header present on all Go files"
    ;;
  fix)
    if (( ${#missing[@]} == 0 )); then
      echo "copyright header already present on all Go files"
      exit 0
    fi
    for file in "${missing[@]}"; do
      add_header "${file}"
      echo "added header: ${file#"${REPO_ROOT}"/}"
    done
    ;;
  *)
    echo "usage: $(basename "$0") [check|fix]" >&2
    exit 2
    ;;
esac
