#!/usr/bin/env bash
# Vendor the two webfonts as Latin, Latin Extended-A and Cyrillic+Greek
# subsets. CSP is `default-src 'self'`, so Google Fonts and any other CDN are
# blocked by design — the woff2 files must live in static/fonts/.
#
# The upstream files carry every script the fonts cover (Inter: 2,852
# codepoints with Cyrillic, Greek and Vietnamese; JetBrains Mono: 1,363 per
# face), 633 KB for the four, and every first visit used to download all of
# it. Each face is cut into three files that static/css/whatismyip.css tells
# apart with `unicode-range`: a Latin one (Google Fonts' `latin` range plus
# the four symbols the page writes itself) that every page fetches, a Latin
# Extended-A one (U+0100-017F and the Romanian comma-below letters
# U+0218-021B: Łódź, Plzeň, İzmir, A.Ş.) and a Cyrillic+Greek one (Google
# Fonts' `cyrillic` + `greek` ranges), each fetched only when such text is on
# the page. Characters outside all three fall back to the system fonts, as CJK
# always has. The unsubsetted originals stay in $TMP: the Dockerfile copies
# static/ whole, so anything left in static/fonts/ ships.
#
# fonttools is a maintainer tool, run through `uvx` and not a project
# dependency: this script is its only use, and the test suite only reads the
# files it leaves (tests/test_page.py::TestDesignTokens). Needs curl, unzip
# and uv (https://docs.astral.sh/uv/); the first run also fetches fonttools
# and brotli from PyPI.
set -euo pipefail

INTER_VERSION="4.1"
JETBRAINS_VERSION="2.304"
DEST="static/fonts"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Google Fonts' `latin` subset plus what the page writes itself beyond it:
# U+2192 → (viewmodel's "A → ip" tag), U+221E ∞ and U+2248 ≈ (the map's
# distance label, the fingerprint panel) and U+25B8 ▸ (the accordion marker).
# Then Latin Extended-A, and Google Fonts' `cyrillic` and `greek` subsets.
# static/css/whatismyip.css repeats the three lists as unicode-range, and
# tests/test_page.py checks they match.
LATIN="U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191-2193,U+2212,U+2215,U+221E,U+2248,U+25B8,U+FEFF,U+FFFD"
EXTENDED_A="U+0100-017F,U+0218-021B"
CYRILLIC_GREEK="U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116,U+0370-0377,U+037A-037F,U+0384-038A,U+038C,U+038E-03A1,U+03A3-03FF"

command -v uvx >/dev/null || {
  echo "uvx not found: install uv (https://docs.astral.sh/uv/)" >&2
  exit 1
}

mkdir -p "$DEST" "$TMP/src"

curl -fsSL -o "$TMP/inter.zip" \
  "https://github.com/rsms/inter/releases/download/v${INTER_VERSION}/Inter-${INTER_VERSION}.zip"
unzip -j -o "$TMP/inter.zip" "web/InterVariable.woff2" -d "$TMP/src"

curl -fsSL -o "$TMP/jetbrains.zip" \
  "https://github.com/JetBrains/JetBrainsMono/releases/download/v${JETBRAINS_VERSION}/JetBrainsMono-${JETBRAINS_VERSION}.zip"
unzip -j -o "$TMP/jetbrains.zip" \
  "fonts/webfonts/JetBrainsMono-Regular.woff2" \
  "fonts/webfonts/JetBrainsMono-Medium.woff2" \
  "fonts/webfonts/JetBrainsMono-SemiBold.woff2" -d "$TMP/src"

# subset <face> <suffix> <unicode ranges>:
#   $TMP/src/<face>.woff2 -> $DEST/<face>-<suffix>.woff2
# --layout-features='*' keeps every OpenType feature (kerning, tnum, Inter's
# cv/ss sets); the variation tables (Inter's opsz and wght axes) are kept by
# default. --name-IDs='*' keeps the whole name table, so the OFL notice (name
# IDs 13 and 14) travels with every file; it costs under 1 KB for all four
# Latin files.
subset() {
  uvx --from fonttools --with brotli pyftsubset "$TMP/src/$1.woff2" \
    --unicodes="$3" --flavor=woff2 --layout-features='*' --name-IDs='*' \
    --output-file="$DEST/$1-$2.woff2"
}

for face in InterVariable JetBrainsMono-Regular JetBrainsMono-Medium JetBrainsMono-SemiBold; do
  subset "$face" latin "$LATIN"
  subset "$face" extended-a "$EXTENDED_A"
  subset "$face" cyrillic-greek "$CYRILLIC_GREEK"
done

ls -la "$DEST"
