#!/bin/bash
# Single source of truth for the checks: runs the same locally and in CI (.github/workflows/check.yml).
set -euo pipefail
cd "$(dirname "$0")/.."

LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
APP=build/ci/Build/Products/Debug/Sigil.app

echo "==> SigilCore: build and test"
command -v gpg >/dev/null || { echo "gpg not found on PATH; the SigilCore tests need it (brew install gnupg)." >&2; exit 1; }
(cd SigilCore && swift build && swift test)

echo "==> Shellcheck"
if command -v shellcheck >/dev/null; then
    shellcheck scripts/*.sh
else
    echo "shellcheck not installed; skipping."
fi

echo "==> Xcode: unsigned Debug build"
if [ -z "${CI:-}" ] && pgrep -x Mail >/dev/null; then
    echo "WARNING: Mail is running; skipping the Xcode build so the running Mail extension is not disturbed." >&2
    exit 0
fi
xcodegen generate
xcodebuild -project Sigil.xcodeproj -scheme Sigil -configuration Debug -derivedDataPath build/ci \
    CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build

if [ -z "${CI:-}" ]; then
    # Keep this throwaway build from showing up as an extra extension in Mail.
    pluginkit -r "$APP/Contents/PlugIns/SigilExtension.appex" 2>/dev/null || true
    "$LSREGISTER" -u "$APP" 2>/dev/null || true
fi
echo "All checks passed."
