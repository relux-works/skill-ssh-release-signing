#!/bin/sh
# Run the unit tests in an isolated HOME and config dir (never the caller's own seats or units).
set -eu
here=$(cd "$(dirname "$0")/.." && pwd -P)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/release-sig-tests.XXXXXX")
scratch=$(cd "$scratch" && pwd -P)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/home" "$scratch/config" "$scratch/tmp"
HOME="$scratch/home" XDG_CONFIG_HOME="$scratch/config" TMPDIR="$scratch/tmp" \
  python3 -I -m unittest discover -s "$here/tests" -p 'test_*.py' -v
