#!/bin/bash
set -euo pipefail

usage() {
    echo "Usage: bash packaging/copy_tipa_to_device.sh [--no-build] [DEVICE_UDID]"
    echo "Build, copy to /var/mobile/Media through USB, and verify by reading back."
    echo "After verification, remove older OSPinOverload packages only."
    echo "Does not install the app or change system trust rules."
}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD=1
DEVICE=""
for argument in "$@"; do
    case "$argument" in
        --help|-h) usage; exit 0 ;;
        --no-build) BUILD=0 ;;
        --*) echo "Unknown option: $argument" >&2; usage >&2; exit 64 ;;
        *)
            if [ -n "$DEVICE" ]; then echo "Specify only one device." >&2; exit 64; fi
            DEVICE="$argument"
            ;;
    esac
done
for tool in idevice_id afcclient python3; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
DEVICE_LIST="$(idevice_id -l)"
DEVICES=()
while IFS= read -r value; do
    if [ -n "$value" ]; then DEVICES+=("$value"); fi
done <<<"$DEVICE_LIST"
if [ "${#DEVICES[@]}" -eq 0 ]; then
    echo "No USB device found. Connect, unlock, and trust this Mac first." >&2
    exit 1
fi
if [ -z "$DEVICE" ]; then
    if [ "${#DEVICES[@]}" -ne 1 ]; then
        echo "Multiple USB devices found. Specify the target DEVICE_UDID." >&2
        exit 1
    fi
    DEVICE="${DEVICES[0]}"
elif ! printf '%s\n' "${DEVICES[@]}" | grep -Fxq -- "$DEVICE"; then
    echo "The specified device is not connected through USB." >&2
    exit 1
fi
if [ "$BUILD" -eq 1 ]; then bash "$ROOT/packaging/build_tipa.sh"; fi
SOURCE_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$ROOT/Resources/Info.plist")"
if [[ ! "$SOURCE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "Invalid app version." >&2; exit 1; fi
PACKAGE="$ROOT/Build/OSPinOverload-$SOURCE_VERSION.tipa"
if [ ! -f "$PACKAGE" ]; then
    echo "Package not found. Omit --no-build to build it first." >&2
    exit 1
fi
METADATA="$(python3 - "$PACKAGE" "$ROOT/Resources/Info.plist" <<'PY'
import hashlib, pathlib, plistlib, re, sys, uuid, zipfile
package = pathlib.Path(sys.argv[1])
source = plistlib.loads(pathlib.Path(sys.argv[2]).read_bytes())
with zipfile.ZipFile(package) as archive:
    if archive.testzip() is not None:
        raise SystemExit("Package ZIP integrity failed")
    info = plistlib.loads(archive.read("Payload/OSPinOverload.app/Info.plist"))
    if info["CFBundleIdentifier"] != "com.dkjone.OSPinOverload":
        raise SystemExit("Unexpected package bundle identifier")
    version = info["CFBundleShortVersionString"]
    if version != source["CFBundleShortVersionString"] or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit("Package version differs from source")
    build = info["CFBundleVersion"]
    if build != source["CFBundleVersion"] or not re.fullmatch(r"\d+", build):
        raise SystemExit("Package build differs from source")
print(version, build, hashlib.sha256(package.read_bytes()).hexdigest(), uuid.uuid4().hex[:12], sep="\t")
PY
)"
IFS=$'\t' read -r VERSION APP_BUILD HASH NONCE <<<"$METADATA"
DESTINATION="OSPinOverload-$VERSION-build$APP_BUILD-${HASH:0:12}-$NONCE.tipa"
TRANSFER="$(mktemp -d "$ROOT/Build/device-copy.XXXXXX")"
cp "$PACKAGE" "$TRANSFER/upload.tipa"
python3 - "$TRANSFER/upload.tipa" "$HASH" <<'PY'
import hashlib, pathlib, sys
if hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit("Package changed while preparing transfer; rerun with a stable build.")
PY
if ! (
    cd "$TRANSFER"
    printf 'put upload.tipa %s\nget %s verified.tipa\nquit\n' "$DESTINATION" "$DESTINATION" |
        afcclient -u "$DEVICE"
) >"$TRANSFER/transfer.log" 2>&1; then
    cat "$TRANSFER/transfer.log" >&2
    echo "USB transfer failed; evidence retained at $TRANSFER" >&2
    exit 1
fi
if grep -E 'Error:|ERROR:|Failed to' "$TRANSFER/transfer.log" >&2; then
    echo "USB transfer reported an error; evidence retained at $TRANSFER" >&2
    exit 1
fi
python3 - "$TRANSFER" "$DESTINATION" "$HASH" "$VERSION" "$APP_BUILD" <<'PY'
import datetime, hashlib, json, pathlib, sys
directory = pathlib.Path(sys.argv[1])
verified = directory / "verified.tipa"
if not verified.is_file():
    raise SystemExit(f"No read-back file; transfer is unverified. See {directory / 'transfer.log'}")
data = verified.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != sys.argv[3]:
    raise SystemExit(f"Read-back SHA256 mismatch; retained files at {directory}")
receipt = {
    "receiptFormatVersion": 1,
    "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "appVersion": sys.argv[4],
    "appBuild": sys.argv[5],
    "transport": "USB AFC",
    "devicePath": f"/var/mobile/Media/{sys.argv[2]}",
    "byteCount": len(data),
    "sha256": digest,
    "readBackVerified": True,
    "installed": False,
    "cleanupComplete": False,
}
(directory / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
print("Copied and SHA256 verified:", receipt["devicePath"])
print("Transfer receipt:", directory / "receipt.json")
PY
python3 "$ROOT/packaging/device_artifacts.py" cleanup-packages "$DEVICE" "$TRANSFER/receipt.json"
rm "$TRANSFER/upload.tipa" "$TRANSFER/verified.tipa"
echo "Open the device path in Filza and share/open the .tipa with TrollStore to install."
