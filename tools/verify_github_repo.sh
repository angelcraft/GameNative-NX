#!/usr/bin/env bash
set -euo pipefail

required=(
  .github/workflows/build.yml
  Makefile
  source/main.cpp
  README.md
  THIRD_PARTY_NOTICES.md
  icon.png
)

for f in "${required[@]}"; do
  test -f "$f" || { echo "Missing: $f" >&2; exit 1; }
done

echo "Repository layout looks ready for GitHub Actions."
echo "Note: third_party/libsolder is fetched by CI; it is intentionally not vendored."
