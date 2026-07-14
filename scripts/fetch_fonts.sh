#!/usr/bin/env bash
# Vendor the two webfonts. CSP is `default-src 'self'`, so Google Fonts and any
# other CDN are blocked by design — the woff2 files must live in static/fonts/.
set -euo pipefail

INTER_VERSION="4.1"
JETBRAINS_VERSION="2.304"
DEST="static/fonts"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$DEST"

curl -fsSL -o "$TMP/inter.zip" \
  "https://github.com/rsms/inter/releases/download/v${INTER_VERSION}/Inter-${INTER_VERSION}.zip"
unzip -j -o "$TMP/inter.zip" "web/InterVariable.woff2" -d "$DEST"

curl -fsSL -o "$TMP/jetbrains.zip" \
  "https://github.com/JetBrains/JetBrainsMono/releases/download/v${JETBRAINS_VERSION}/JetBrainsMono-${JETBRAINS_VERSION}.zip"
unzip -j -o "$TMP/jetbrains.zip" \
  "fonts/webfonts/JetBrainsMono-Regular.woff2" \
  "fonts/webfonts/JetBrainsMono-Medium.woff2" \
  "fonts/webfonts/JetBrainsMono-SemiBold.woff2" -d "$DEST"

ls -la "$DEST"
