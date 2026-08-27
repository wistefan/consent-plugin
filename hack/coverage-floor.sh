#!/usr/bin/env bash
#
# Fail when total statement coverage is below a floor.
#
# Coverage was previously uploaded as a CI artifact and never asserted, so a
# whole code path could sit at 0% without anything noticing. This turns the
# number into a gate.
#
# Usage: coverage-floor.sh <coverage-profile> <minimum-percent>

set -euo pipefail

profile="${1:?usage: coverage-floor.sh <coverage-profile> <minimum-percent>}"
floor="${2:?usage: coverage-floor.sh <coverage-profile> <minimum-percent>}"

total="$(go tool cover -func="${profile}" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')"

if [[ -z "${total}" ]]; then
  echo "coverage-floor: could not read a total from ${profile}" >&2
  exit 1
fi

# awk rather than bash arithmetic: the percentages are fractional.
if awk -v total="${total}" -v floor="${floor}" 'BEGIN { exit !(total < floor) }'; then
  echo "coverage-floor: total coverage ${total}% is below the ${floor}% floor" >&2
  exit 1
fi

echo "coverage-floor: total coverage ${total}% meets the ${floor}% floor"
