#!/bin/bash
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    echo "Usage: bash packaging/pull_device_logs.sh [DEVICE_UDID]"
    echo "Read only the latest export and verify its build/session and all files."
    echo "No device writes or root commands. Requires a fresh export from the current build."
    exit 0
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$#" -gt 1 ] || [[ "${1:-}" == --* ]]; then
    echo "Specify at most one DEVICE_UDID, or --help." >&2
    exit 64
fi
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
DEVICE="${1:-}"
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
mkdir -p "$ROOT/Build"
DESTINATION="$(mktemp -d "$ROOT/Build/device-logs.XXXXXX")"
if ! (
    cd "$DESTINATION"
    printf 'get OSPinOverload/Diagnostics/current-session.json current-session.json\nget -r OSPinOverload/Exports/Latest Latest\nget OSPinOverload/Diagnostics/current-session.json session-after.json\nquit\n' | afcclient -u "$DEVICE"
) >"$DESTINATION/transfer.log" 2>&1; then
    cat "$DESTINATION/transfer.log" >&2
    echo "USB download failed; retained evidence at $DESTINATION" >&2
    exit 1
fi
if [ ! -f "$DESTINATION/Latest/receipt.json" ]; then
    cat "$DESTINATION/transfer.log" >&2
    echo "No latest export. Upgrade to the current build, run diagnostics, then export first." >&2
    exit 1
fi
if grep -E 'Error:|ERROR:|Failed to' "$DESTINATION/transfer.log" >&2; then
    echo "Transfer contains errors; retained partial files for diagnosis." >&2
    exit 1
fi
if ! cmp -s "$DESTINATION/current-session.json" "$DESTINATION/session-after.json"; then
    echo "Diagnostic session changed during download; export and download again." >&2
    exit 1
fi
python3 "$ROOT/packaging/device_artifacts.py" verify-latest "$DESTINATION/Latest" "$ROOT/Resources/Info.plist" "$DESTINATION/current-session.json"
echo "Device logs: $DESTINATION"
