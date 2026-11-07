#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="$ROOT/Build"
RUNTIME="${OSPIN_SIMULATOR_RUNTIME:-com.apple.CoreSimulator.SimRuntime.iOS-18-6}"
mkdir -p "$OUTPUT"
if ! xcodebuild -quiet -project "$ROOT/OSPinOverload.xcodeproj" -scheme OSPinOverload \
    -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$OUTPUT/SimulatorDerivedData" CODE_SIGNING_ALLOWED=NO build \
    >"$OUTPUT/simulator-build.log" 2>&1; then
    tail -80 "$OUTPUT/simulator-build.log" >&2
    exit 1
fi
SIMULATOR="$(xcrun simctl create OSPinOverload-validation com.apple.CoreSimulator.SimDeviceType.iPhone-11 "$RUNTIME")"
cleanup() {
    xcrun simctl shutdown "$SIMULATOR" >/dev/null 2>&1 || true
    xcrun simctl delete "$SIMULATOR"
}
trap cleanup EXIT
xcrun simctl boot "$SIMULATOR"
xcrun simctl bootstatus "$SIMULATOR" -b >/dev/null
xcrun simctl install "$SIMULATOR" "$OUTPUT/SimulatorDerivedData/Build/Products/Debug-iphonesimulator/OSPinOverload.app"
CONTAINER="$(xcrun simctl get_app_container "$SIMULATOR" com.dkjone.OSPinOverload data)"
mkdir -p "$OUTPUT/simulator-validation"
xcrun simctl launch "$SIMULATOR" com.dkjone.OSPinOverload
sleep 2
xcrun simctl io "$SIMULATOR" screenshot "$OUTPUT/simulator-validation/home.png"
xcrun simctl ui "$SIMULATOR" appearance dark
xcrun simctl ui "$SIMULATOR" content_size accessibility-extra-extra-large
sleep 1
xcrun simctl io "$SIMULATOR" screenshot "$OUTPUT/simulator-validation/home-dark-large.png"
xcrun simctl ui "$SIMULATOR" appearance light
xcrun simctl ui "$SIMULATOR" content_size large
xcrun simctl terminate "$SIMULATOR" com.dkjone.OSPinOverload
xcrun simctl launch "$SIMULATOR" com.dkjone.OSPinOverload --smoke-test-home-footer
sleep 2
xcrun simctl io "$SIMULATOR" screenshot "$OUTPUT/simulator-validation/home-footer.png"
xcrun simctl terminate "$SIMULATOR" com.dkjone.OSPinOverload
xcrun simctl ui "$SIMULATOR" appearance dark
xcrun simctl ui "$SIMULATOR" content_size accessibility-extra-extra-large
xcrun simctl launch "$SIMULATOR" com.dkjone.OSPinOverload --smoke-test-home-footer
sleep 2
xcrun simctl io "$SIMULATOR" screenshot "$OUTPUT/simulator-validation/home-footer-dark-large.png"
xcrun simctl terminate "$SIMULATOR" com.dkjone.OSPinOverload
xcrun simctl ui "$SIMULATOR" appearance light
xcrun simctl ui "$SIMULATOR" content_size large
for MODE in diagnose prepare apply permissions; do
xcrun simctl launch "$SIMULATOR" com.dkjone.OSPinOverload "--smoke-test-$MODE" --smoke-test-export
python3 - "$CONTAINER" "$OUTPUT" "$MODE" <<'PY'
import json, pathlib, plistlib, shutil, sys, time
container = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2]) / "simulator-validation"
media = container / "Documents" / "OSPinOverload"
sessions = media / "Diagnostics" / "Sessions"
deadline = time.monotonic() + 45
session = None
failure = None
receipt_path = media / "Exports/Latest/receipt.json"
previous_path = output / "export/receipt.json"
previous_id = json.loads(previous_path.read_text())["exportID"] if previous_path.exists() else None
while time.monotonic() < deadline:
    reports = list(sessions.glob("*/report.json"))
    failures = list(sessions.glob("*/summary.txt"))
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        if receipt["exportID"] == previous_id:
            time.sleep(0.25)
            continue
        session = sessions / receipt["sessionID"]
        app_log = session / "app.log"
        if app_log.exists() and "导出完成" in app_log.read_text():
            break
    elif failures and not reports:
        session = failures[0].parent
        failure = failures[0].read_text()
        break
    time.sleep(0.25)
if session is None:
    for log in container.glob("Documents/OSPinOverload/**/*.log"):
        print(log, log.read_text())
    raise SystemExit("Simulator report not produced")
output.mkdir(exist_ok=True)
for source in session.iterdir():
    shutil.copy2(source, output / source.name)
if failure is not None:
    print((session / "app.log").read_text())
    worker_log = session / "worker.log"
    if worker_log.exists():
        print(worker_log.read_text())
    raise SystemExit(failure)
report = json.loads((session / "report.json").read_text())
assert report["status"] == "failed", report
assert report["identity"]["effectiveUID"] != 0, report
assert report["database"]["writeAccess"] == "not_tested", report
if sys.argv[3] == "permissions":
    assert {p["profile"] for p in report["accessProbes"]} == {"root", "trustd"}
    assert report["accessFailures"] == []
    for probe in report["accessProbes"]:
        assert probe["identityVerified"] is False
        assert probe["status"] == "failed"
        assert probe["paths"] == [] and "open" not in probe
        assert "身份不匹配" in probe["skippedReason"]
        runtime = probe["runtimeEntitlement"]
        assert runtime["key"] == "com.apple.private.security.storage.trustd"
        assert runtime["processID"] == probe["identity"]["pid"]
        assert runtime["method"] == "csops_self_xml"
        assert runtime["state"] in {"boolean", "absent", "unavailable"}
        if runtime["state"] != "boolean":
            assert "value" not in runtime
    assert "profile=root" in (session / "worker.log").read_text()
    assert "profile=trustd" in (session / "worker.log").read_text()
    assert "open O_RDWR" not in (session / "worker.log").read_text()
else:
    assert any(c["name"] == "root_identity" and c["level"] == "fail" for c in report["checks"]), report
    assert "root 验证失败" in (session / "worker.log").read_text()
assert not (session / "pinningrules.snapshot.sqlite3").exists()
assert "报告已持久化 status=failed" in (session / "app.log").read_text()
assert "posix_spawn return=0" in (session / "app.log").read_text()
import hashlib
receipt = json.loads(receipt_path.read_text())
assert receipt["receiptFormatVersion"] == 1
assert receipt["sessionID"] == session.name
info = plistlib.loads((pathlib.Path(sys.argv[2]).parent / "Resources/Info.plist").read_bytes())
assert receipt["appVersion"] == info["CFBundleShortVersionString"]
assert receipt["appBuild"] == info["CFBundleVersion"]
assert report["appBuild"] == info["CFBundleVersion"]
assert report["operation"] == sys.argv[3]
assert not list((media / "Baselines").glob("*/baseline-receipt.json"))
assert not (session / "plan.json").exists()
if sys.argv[3] in {"prepare", "apply"}:
    assert any(c["name"] == "preparation_baseline" and c["level"] == "fail" for c in report["checks"])
    assert "未启动预检 helper" in (session / "app.log").read_text()
for name in ["app.log", "worker.log"]:
    assert f"version={info['CFBundleShortVersionString']} build={info['CFBundleVersion']}" in (session / name).read_text()
assert len(list((media / "Exports").iterdir())) == 1
assert "pinningrules.snapshot.sqlite3" in receipt["missingSessionFiles"]
assert "UIActivityViewController" not in (pathlib.Path(sys.argv[2]).parent / "Sources/OSPinApp/DiagnosticViewController.swift").read_text()
for entry in receipt["files"]:
    data = (receipt_path.parent / entry["name"]).read_bytes()
    assert len(data) == entry["byteCount"]
    assert hashlib.sha256(data).hexdigest() == entry["sha256"]
shutil.copytree(receipt_path.parent, output / "export", dirs_exist_ok=True)
print("Simulator IPC, non-root failure, persistent logs and Foundation-only export verified.")
PY
python3 "$ROOT/packaging/device_artifacts.py" verify-latest "$OUTPUT/simulator-validation/export" "$ROOT/Resources/Info.plist" "$CONTAINER/Documents/OSPinOverload/Diagnostics/current-session.json"
if [ "$MODE" != permissions ]; then xcrun simctl terminate "$SIMULATOR" com.dkjone.OSPinOverload; fi
done
xcrun simctl terminate "$SIMULATOR" com.dkjone.OSPinOverload
for FEEDBACK_MODE in save share; do
if [ "$FEEDBACK_MODE" = share ]; then
    xcrun simctl launch "$SIMULATOR" com.dkjone.OSPinOverload --smoke-test-feedback --smoke-test-share
else
    xcrun simctl launch "$SIMULATOR" com.dkjone.OSPinOverload --smoke-test-feedback
fi
python3 - "$CONTAINER" "$OUTPUT" "$FEEDBACK_MODE" <<'PY'
import json, pathlib, plistlib, re, shutil, sys, time, zipfile
media = pathlib.Path(sys.argv[1]) / "Documents/OSPinOverload"
deadline = time.monotonic() + 40
while time.monotonic() < deadline:
    packages = sorted((media / "Exports/Feedback").glob("*.zip"), key=lambda p: p.stat().st_mtime_ns)
    log = media / "Diagnostics/app.log"
    if packages and log.exists() and (sys.argv[3] == "save" or (
        "系统分享面板已呈现；已排除 AirDrop" in log.read_text()
        and "分享附件名称与 ZIP 内容已核对" in log.read_text()
    )):
        break
    time.sleep(0.25)
else:
    raise SystemExit("Feedback ZIP or system share presentation was not produced")
package = packages[-1]
info = plistlib.loads((pathlib.Path(sys.argv[2]).parent / "Resources/Info.plist").read_bytes())
assert re.fullmatch(r"OSPinOverload-feedback-v" + re.escape(info["CFBundleShortVersionString"]) +
                    r"-\d{8}-\d{6}Z-[0-9A-F]{8}\.zip", package.name), package.name
if sys.argv[3] == "share":
    assert f"filename={package.name}" in log.read_text(), "Shared attachment name differs from saved ZIP"
if sys.argv[3] == "save":
    time.sleep(1)
    assert "系统分享面板已呈现" not in log.read_text(), "Save-only fallback unexpectedly presented sharing"
with zipfile.ZipFile(package) as archive:
    assert archive.testzip() is None
    assert set(archive.namelist()) == {"feedback.json", "events.json", "PRIVACY.txt"}
    report = json.loads(archive.read("feedback.json"))
    assert report["reportAvailable"] is True
    assert report["formatVersion"] == 1
    assert report["operation"] == "permissions"
    assert re.fullmatch(r"\d+\.\d+\.\d+", report["systemVersion"])
    for data in [archive.read(name) for name in archive.namelist()]:
        for forbidden in [b"baselineID", b"receiptSHA256", b"sourcePath", b"sessionID", b"policiesPropertyListXML"]:
            assert forbidden not in data
    assert "rawLogs" in report["excluded"] and "database" in report["excluded"]
shutil.copy2(package, pathlib.Path(sys.argv[2]) / "simulator-validation/feedback.zip")
print("Feedback ZIP name, CRC, exact whitelist and redacted schema verified:", sys.argv[3])
PY
if [ "$FEEDBACK_MODE" = save ]; then xcrun simctl terminate "$SIMULATOR" com.dkjone.OSPinOverload; fi
done
xcrun simctl io "$SIMULATOR" screenshot "$OUTPUT/simulator-validation/share.png"
APP="$(xcrun simctl get_app_container "$SIMULATOR" com.dkjone.OSPinOverload app)"
for MODE in apply restore; do
if xcrun simctl spawn "$SIMULATOR" "$APP/OSPinOverload" "--$MODE" \
    00000000-0000-0000-0000-000000000001 00000000-0000-0000-0000-000000000002 \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    > "$OUTPUT/simulator-validation/$MODE-worker.json" 2> "$OUTPUT/simulator-validation/$MODE-worker.log"; then
    echo "Expected non-root change worker rejection" >&2
    exit 1
else
    test "$?" -eq 2
fi
python3 - "$OUTPUT/simulator-validation/$MODE-worker.json" "$MODE" <<'PY'
import json, pathlib, sys
e = json.loads(pathlib.Path(sys.argv[1]).read_text())
r = e["report"]
assert r["operation"] == sys.argv[2] and r["status"] == "failed"
assert r["identity"]["effectiveUID"] != 0
assert r["change"]["commitState"] == "notAttempted" and r["change"]["verified"] is False
assert r["database"]["writeAccess"] == "not_committed"
assert "snapshot" not in e
assert "root 验证失败" in r["change"]["detail"]
print("Actual change worker dispatch and root-before-I/O gate verified:", sys.argv[2])
PY
done
xcrun simctl io "$SIMULATOR" screenshot "$OUTPUT/simulator-validation/screen.png"
cp "$CONTAINER/Documents/OSPinOverload/Diagnostics/current-session.json" "$OUTPUT/simulator-validation/session-before-link.json"
xcrun simctl terminate "$SIMULATOR" com.dkjone.OSPinOverload
xcrun simctl launch "$SIMULATOR" com.dkjone.OSPinOverload --smoke-test-project-link
python3 - "$CONTAINER" "$OUTPUT" <<'PY'
import pathlib, sys, time
media = pathlib.Path(sys.argv[1]) / "Documents/OSPinOverload"
expected = "项目主页链接已交给系统 url=https://github.com/DKJone/OSPinOverload"
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    if expected in (media / "Diagnostics/app.log").read_text():
        break
    time.sleep(0.25)
else:
    raise SystemExit("GitHub footer button did not hand off the exact homepage URL")
assert (media / "Diagnostics/current-session.json").read_bytes() == (
    pathlib.Path(sys.argv[2]) / "simulator-validation/session-before-link.json"
).read_bytes(), "Opening the homepage changed the diagnostic session"
print("Actual GitHub footer button handed off the exact URL without starting diagnostics.")
PY
