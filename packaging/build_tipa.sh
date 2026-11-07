#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="$ROOT/Build"
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$ROOT/Resources/Info.plist")"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "Invalid app version." >&2; exit 1; fi
command -v ldid >/dev/null || { echo "Missing ldid. Install it before packaging." >&2; exit 1; }
mkdir -p "$OUTPUT"
if ! xcodebuild -quiet \
    -project "$ROOT/OSPinOverload.xcodeproj" \
    -scheme OSPinOverload -configuration Release \
    -sdk iphoneos -destination 'generic/platform=iOS' \
    -derivedDataPath "$OUTPUT/DerivedData" CODE_SIGNING_ALLOWED=NO \
    build >"$OUTPUT/build.log" 2>&1; then
    tail -80 "$OUTPUT/build.log" >&2
    exit 1
fi
STAGING="$(mktemp -d "$OUTPUT/package.XXXXXX")"
trap 'find "$STAGING" -type f -delete; find "$STAGING" -depth -type d -empty -delete' EXIT
mkdir -p "$STAGING/Payload"
ditto "$OUTPUT/DerivedData/Build/Products/Release-iphoneos/OSPinOverload.app" "$STAGING/Payload/OSPinOverload.app"
ldid -S"$ROOT/Resources/OSPinOverload.entitlements" "$STAGING/Payload/OSPinOverload.app/OSPinOverload"
ldid -e "$STAGING/Payload/OSPinOverload.app/OSPinOverload" >"$OUTPUT/packaged-entitlements.plist"
python3 - "$ROOT/Resources/OSPinOverload.entitlements" "$OUTPUT/packaged-entitlements.plist" <<'PY'
import pathlib, plistlib, sys
expected, signed = [plistlib.loads(pathlib.Path(path).read_bytes()) for path in sys.argv[1:]]
if signed != expected or signed.get("com.apple.private.security.storage.trustd") is not True:
    raise SystemExit("Packaged entitlement declaration does not match the authorized source")
PY
ARCHIVE="$OUTPUT/OSPinOverload-$VERSION.tipa"
if [ -f "$ARCHIVE" ]; then rm "$ARCHIVE"; fi
(cd "$STAGING" && zip -qr "$ARCHIVE" Payload)
unzip -tq "$ARCHIVE"
echo "$ARCHIVE"
