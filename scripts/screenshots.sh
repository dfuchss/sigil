#!/bin/bash
# Regenerates the README screenshots in Docs/screenshots/ from the Debug build, using the app's `--demo` data
# (fixed, made-up; never the user's keys). Build first:
#   xcodebuild -project Sigil.xcodeproj -scheme Sigil -configuration Debug -allowProvisioningUpdates -derivedDataPath build build
set -euo pipefail
cd "$(dirname "$0")/.."

APP="build/Build/Products/Debug/Sigil Dev.app"
OUT=Docs/screenshots
WINID=build/winid

if pgrep -x Mail >/dev/null; then
    echo "Mail is running; quit it first." >&2
    exit 1
fi
if [ ! -d "$APP" ]; then
    echo "Debug build missing. Build it first:" >&2
    echo "  xcodebuild -project Sigil.xcodeproj -scheme Sigil -configuration Debug -allowProvisioningUpdates -derivedDataPath build build" >&2
    exit 1
fi
if [ ! -x "$WINID" ] || [ scripts/winid.swift -nt "$WINID" ]; then
    swiftc -O scripts/winid.swift -o "$WINID"
fi
mkdir -p "$OUT"

quit_sigil() {
    pkill -x "Sigil Dev" 2>/dev/null || true
    for _ in $(seq 20); do pgrep -x "Sigil Dev" >/dev/null || return 0; sleep 0.25; done
    pkill -9 -x "Sigil Dev" 2>/dev/null || true
}
trap quit_sigil EXIT

# view -> window title filter ("" = frontmost Sigil Dev window)
title_for() {
    case "$1" in
        about) echo "About" ;;
        help) echo "Getting started" ;;
        settings) echo "Advanced" ;;
        *) echo "" ;;
    esac
}

quit_sigil
for view in overview publickeys missing findkey about help settings; do
    for mode in light dark; do
        open -n "$APP" --args --demo --appearance "$mode" --open "$view"
        id=""
        for _ in $(seq 40); do
            id=$("$WINID" "$(title_for "$view")" || true)
            [ -n "$id" ] && break
            sleep 0.25
        done
        if [ -z "$id" ]; then echo "No window for $view ($mode)" >&2; exit 1; fi
        sleep 2   # let the demo data and sheets render
        id=$("$WINID" "$(title_for "$view")" || echo "$id")
        file="$OUT/$view-$mode.png"
        screencapture -o -l "$id" "$file"
        width=$(sips -g pixelWidth "$file" | awk '/pixelWidth/ {print $2}')
        if [ "$width" -gt 1400 ]; then sips --resampleWidth 1400 "$file" >/dev/null; fi
        echo "wrote $file"
        quit_sigil
    done
done
