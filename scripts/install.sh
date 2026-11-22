#!/bin/bash
# Builds the Release app and installs it to /Applications/Sigil.app (the only copy that should be registered with
# Mail and as a Login Item). Debug builds ("Sigil Dev") have their own identity and are unaffected.
# Never calls sfltool (it needs an admin password).
set -euo pipefail
cd "$(dirname "$0")/.."

LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
BUILT=build/release/Build/Products/Release/Sigil.app
DEST=/Applications/Sigil.app
LABEL=org.fuchss.sigil.helper

if pgrep -x Mail >/dev/null; then
    echo "Mail is running; quit it first." >&2
    exit 1
fi

xcodegen generate
xcodebuild -project Sigil.xcodeproj -scheme Sigil -configuration Release -allowProvisioningUpdates \
    -derivedDataPath build/release build

[ -d "$BUILT" ] || { echo "Release build missing: $BUILT" >&2; exit 1; }
codesign --verify --deep --strict --verbose=2 "$BUILT"
codesign -dv "$BUILT" 2>&1 | grep -E "^(Identifier|TeamIdentifier)="

# Quit a running Sigil, then replace the installed copy.
osascript -e 'tell application id "org.fuchss.sigil" to quit' >/dev/null 2>&1 || true
pkill -x Sigil 2>/dev/null || true
for _ in $(seq 20); do pgrep -x Sigil >/dev/null || break; sleep 0.25; done
# Remove the old copy first: ditto merges, so files dropped from the new build would survive inside the bundle.
rm -rf "$DEST"
ditto "$BUILT" "$DEST"
# Verify what is actually installed, not only the build product.
codesign --verify --deep --strict --verbose=2 "$DEST"

# Only /Applications may be registered: drop the build copy's registrations.
"$LSREGISTER" -f "$DEST"
"$LSREGISTER" -u "$BUILT" || true
pluginkit -r "$BUILT/Contents/PlugIns/SigilExtension.appex" 2>/dev/null || true

# Re-register the helper from /Applications.
open "$DEST" --args --register-helper
sleep 3
# A helper still running from the previous install keeps the old binary until it is restarted.
launchctl kickstart -k "gui/$UID/$LABEL" 2>/dev/null || echo "Helper not loaded yet; launchd starts it on demand." >&2

echo "--- launchctl print gui/$UID/$LABEL"
if out=$(launchctl print "gui/$UID/$LABEL" 2>&1); then
    echo "$out" | grep -E "^\s*(program|path|state|pid) =" || echo "$out" | head -20
else
    echo "Helper not loaded yet (launchd may need approval or a logout)." >&2
fi
echo "--- processes running SigilHelper"
pids=$(pgrep -x SigilHelper || true)
if [ -n "$pids" ]; then
    for pid in $pids; do lsof -p "$pid" 2>/dev/null | awk '$4 == "txt" && /SigilHelper/ {print "pid '"$pid"': " $NF}'; done
else
    echo "(not running yet; launchd starts it on demand when Sigil or Mail connects)"
fi

cat <<MSG

Installed $DEST. Next steps:
  1. Open Sigil, check Settings > General: the helper should read "Enabled" (approve it under
     System Settings > General > Login Items & Extensions if it asks).
  2. Start Mail and enable "Sigil" under Mail > Settings > Extensions.
Note: after moving an existing install, launchd may still cache the old path of the helper. If lsof above shows
a path outside /Applications, or the helper does not start, log out and back in (or reboot).
MSG
