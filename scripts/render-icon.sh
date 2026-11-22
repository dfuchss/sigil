#!/bin/bash
# Regenerates App/Assets.xcassets/AppIcon.appiconset from Design/AppIcon.svg (needs Inkscape on the PATH).
set -euo pipefail
cd "$(dirname "$0")/.."
SVG=Design/AppIcon.svg
SET=App/Assets.xcassets/AppIcon.appiconset
mkdir -p "$SET"
command -v inkscape >/dev/null || { echo "inkscape not found (brew install inkscape)" >&2; exit 1; }

images=""
for size in 16 32 128 256 512; do
  for scale in 1 2; do
    px=$((size * scale))
    name="icon_${size}x${size}@${scale}x.png"
    inkscape "$SVG" --export-type=png --export-filename="$SET/$name" -w "$px" -h "$px" >/dev/null 2>&1
    images+="    { \"filename\": \"$name\", \"idiom\": \"mac\", \"scale\": \"${scale}x\", \"size\": \"${size}x${size}\" },
"
  done
done
printf '{\n  "images": [\n%s\n  ],\n  "info": { "author": "xcode", "version": 1 }\n}\n' "${images%,
}" > "$SET/Contents.json"
echo "Rendered $(find "$SET" -maxdepth 1 -name "*.png" | wc -l | tr -d ' ') icons into $SET"
