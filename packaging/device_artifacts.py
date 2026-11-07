import argparse
import hashlib
import json
import pathlib
import plistlib
import re
import subprocess


PACKAGE_NAME = re.compile(
    r"OSPinOverload(?:-\d+\.\d+\.\d+(?:-build\d+)?(?:-[0-9a-f]{12}-[0-9a-f]{12})?)?\.tipa"
)


def afc(device, commands, log):
    result = subprocess.run(
        ["afcclient", "-u", device], input="\n".join([*commands, "quit", ""]),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    with log.open("a") as handle:
        handle.write(result.stdout)
    if result.returncode or re.search(r"Error:|ERROR:|Failed to", result.stdout):
        raise RuntimeError("AFC failed; inspect " + str(log))
    return result.stdout


def package_names(listing):
    return {
        line.removeprefix("afc:/ > ").strip()
        for line in listing.splitlines()
        if PACKAGE_NAME.fullmatch(line.removeprefix("afc:/ > ").strip())
    }


def cleanup_packages(device, receipt_path):
    receipt = json.loads(receipt_path.read_text())
    current = pathlib.PurePosixPath(receipt["devicePath"]).name
    if not receipt["readBackVerified"] or not PACKAGE_NAME.fullmatch(current):
        raise ValueError("Only a verified project package may trigger cleanup")
    log = receipt_path.parent / "cleanup.log"
    names = package_names(afc(device, ["ls"], log))
    if current not in names:
        raise RuntimeError("Verified package missing; refusing to remove older packages")
    obsolete = sorted(names - {current})
    for name in obsolete:
        output = afc(device, ["info " + name], log)
        attributes = json.loads(output[output.index("{"):output.rindex("}") + 1])
        if attributes["st_ifmt"] != "S_IFREG":
            raise RuntimeError("Refusing to delete non-regular package: " + name)
    if obsolete:
        afc(device, ["rm " + name for name in obsolete], log)
    if package_names(afc(device, ["ls"], log)) != {current}:
        raise RuntimeError("Package cleanup incomplete; inspect " + str(log))
    receipt.update(cleanupComplete=True, removedPackages=obsolete)
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print("Old project packages removed:", len(obsolete))


def verify_access_report(report, names):
    forbidden = {"pinningrules.snapshot.sqlite3", "baseline.sqlite3", "baseline-report.json",
                 "baseline-receipt.json", "candidate.sqlite3", "restored.sqlite3", "plan.json"}
    source = "/private/var/protected/trustd/pinningrules.sqlite3"
    if (set(names) & forbidden or report.get("preparation") is not None
        or report.get("database", {}).get("sourcePath") != source
        or report["database"].get("writeAccess") != "not_tested"
        or report["database"].get("snapshotSHA256") is not None):
        raise ValueError("Permission diagnostic scope mismatch")
    probes = report.get("accessProbes", [])
    failures = report.get("accessFailures", [])
    profiles = [entry.get("profile") for entry in probes + failures]
    if len(profiles) != len(set(profiles)) or not set(profiles) <= {"root", "trustd"}:
        raise ValueError("Invalid permission diagnostic profiles")
    for probe in probes:
        expected = 0 if probe["profile"] == "root" else 282
        identity = probe.get("identity", {})
        matches = all(identity.get(key) == expected for key in ["uid", "effectiveUID", "gid", "effectiveGID"])
        if probe.get("identityVerified") is not matches:
            raise ValueError("Permission diagnostic identity mismatch")
        if not matches and (probe.get("status") != "failed" or probe.get("paths") != [] or probe.get("open") is not None):
            raise ValueError("Permission diagnostic accessed paths before identity verification")
        runtime = probe.get("runtimeEntitlement")
        if not isinstance(runtime, dict):
            raise ValueError("Invalid runtime entitlement evidence")
        state = runtime.get("state")
        if (runtime.get("key") != "com.apple.private.security.storage.trustd"
            or runtime.get("method") != "csops_self_xml"
            or type(runtime.get("processID")) is not int or runtime["processID"] <= 0
            or runtime.get("processID") != identity.get("pid")
            or not isinstance(state, str) or state not in {"boolean", "absent", "unavailable"}
            or not isinstance(runtime.get("detail"), str) or not runtime["detail"]
            or type(runtime.get("probeReturnValue")) is not int or type(runtime.get("probeErrno")) is not int):
            raise ValueError("Invalid runtime entitlement evidence")
        if state == "boolean":
            if type(runtime.get("value")) is not bool:
                raise ValueError("Runtime entitlement Boolean is missing or coerced")
        elif runtime.get("value") is not None:
            raise ValueError("Unknown or absent runtime entitlement cannot claim a value")
        if state == "unavailable":
            if probe.get("status") == "complete":
                raise ValueError("Unavailable runtime entitlement claimed complete")
        elif ((runtime.get("probeReturnValue"), runtime.get("probeErrno")) not in {(0, 0), (-1, 34)}
              or type(runtime.get("readReturnValue")) is not int or type(runtime.get("readErrno")) is not int
              or runtime.get("readReturnValue") != 0 or runtime.get("readErrno") != 0
              or type(runtime.get("blobByteCount")) is not int
              or not 9 <= runtime.get("blobByteCount", 0) <= 1024 * 1024):
            raise ValueError("Runtime entitlement result lacks successful kernel read")
    if report.get("status") == "complete":
        if failures or len(probes) != 2 or set(profiles) != {"root", "trustd"}:
            raise ValueError("Incomplete permission comparison claimed complete")
        for probe in probes:
            # Darwin O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, without CREATE/TRUNCATE.
            paths, opened = probe.get("paths", []), probe.get("open")
            expected_paths = ["/private/var/protected", "/private/var/protected/trustd", source]
            if (probe.get("status") != "complete" or probe.get("identityVerified") is not True
                or [entry.get("path") for entry in paths] != expected_paths
                or any(entry.get("statErrno") != 0 or entry.get("statfsErrno") != 0
                       or not entry.get("attributes") or not entry.get("mount") for entry in paths)
                or probe.get("sourceMetadataUnchanged") is not True or probe.get("afterStatErrno") != 0
                or probe.get("afterAttributes") != paths[-1].get("attributes")
                or not opened or opened.get("requestedFlags") != 0x01000106):
                raise ValueError("Incomplete permission probe claimed complete")
            if opened.get("returnValue", -1) < 0:
                if opened.get("openErrno", 0) <= 0:
                    raise ValueError("Permission open denial is missing errno")
            elif (opened.get("openErrno") != 0 or opened.get("getFlagsErrno") != 0
                  or opened.get("getFlagsReturnValue", -1) & 3 != 2
                  or opened.get("descriptorStatErrno") != 0
                  or opened.get("descriptorMatchesSource") is not True
                  or opened.get("descriptorAttributes") != paths[-1].get("attributes")
                  or opened.get("closeReturnValue") != 0 or opened.get("closeErrno") != 0):
                raise ValueError("Permission read-write descriptor not confirmed")


def verify_change_report(report, names, directory):
    if report.get("database", {}).get("sourcePath") != "/private/var/protected/trustd/pinningrules.sqlite3":
        raise ValueError("Rule change source scope mismatch")
    states = {"notAttempted", "committing", "committed", "rolledBack", "unknown"}
    change = report.get("change")
    progress = json.loads((directory / "change-progress.json").read_text()) if "change-progress.json" in names else None
    evidence = change if change is not None else progress
    if evidence is None:
        if report.get("status") not in {"failed", "partial"}:
            raise ValueError("Completed rule change lacks commit evidence")
        return
    if (not isinstance(evidence, dict) or evidence.get("action") != report["operation"]
        or not isinstance(evidence.get("commitState"), str) or evidence["commitState"] not in states
        or type(evidence.get("verified")) is not bool
        or type(evidence.get("alreadyRestored")) is not bool
        or not isinstance(evidence.get("baselineReceiptSHA256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", evidence["baselineReceiptSHA256"])):
        raise ValueError("Invalid rule change evidence")
    if "recovery-reference.json" not in names:
        raise ValueError("Rule change has no durable recovery reference")
    reference = json.loads((directory / "recovery-reference.json").read_text())
    if (reference.get("baselineID") != evidence.get("baselineID")
        or reference.get("receiptSHA256") != evidence["baselineReceiptSHA256"]
        or "baseline-receipt.json" not in names
        or hashlib.sha256((directory / "baseline-receipt.json").read_bytes()).hexdigest() != reference["receiptSHA256"]):
        raise ValueError("Rule change recovery reference mismatch")
    if change is not None and progress is not None and change != progress:
        raise ValueError("Rule change envelope and durable progress disagree")
    if report.get("status") == "complete":
        if (change is None or progress is None or evidence["verified"] is not True
            or not (evidence["commitState"] == "committed"
                    or (report["operation"] == "restore" and evidence["alreadyRestored"] is True
                        and evidence["commitState"] == "notAttempted"))
            or not all(type(report.get("identity", {}).get(key)) is int and report["identity"][key] == 0
                       for key in ["uid", "effectiveUID", "gid", "effectiveGID"])):
            raise ValueError("Unverified or unknown rule change claimed complete")
        baseline = json.loads((directory / "baseline-receipt.json").read_text())
        original_count = baseline["database"]["ruleCount"]
        before = original_count if report["operation"] == "apply" or evidence["alreadyRestored"] else original_count - 1
        after = original_count - 1 if report["operation"] == "apply" else original_count
        if (type(evidence.get("beforeRuleCount")) is not int or type(evidence.get("afterRuleCount")) is not int
            or (evidence["beforeRuleCount"], evidence["afterRuleCount"]) != (before, after)
            or report.get("database", {}).get("ruleCount") != after):
            raise ValueError("Rule change row-count scope mismatch")
        expected_write = "commit_succeeded" if evidence["commitState"] == "committed" else "not_committed"
        if report["database"].get("writeAccess") != expected_write:
            raise ValueError("Rule change commit declaration mismatch")


def verify_latest(directory, info_path, current_session):
    info = plistlib.loads(info_path.read_bytes())
    receipt = json.loads((directory / "receipt.json").read_text())
    if receipt["receiptFormatVersion"] != 1:
        raise ValueError("Unsupported export receipt")
    if (receipt["appVersion"], receipt.get("appBuild")) != (
        info["CFBundleShortVersionString"], info["CFBundleVersion"]
    ):
        raise ValueError("Export is from an older build; upgrade, run diagnostics and export again")
    metadata = json.loads(current_session.read_text())
    if any(metadata[key] != receipt[key] for key in ["sessionID", "appVersion", "appBuild"]):
        raise ValueError("Latest export is not from the current diagnostic session; export again")
    allowed = {"summary.txt", "report.json", "app.log", "worker.log",
               "pinningrules.snapshot.sqlite3", "application.log", "baseline.sqlite3",
               "baseline-report.json", "baseline-receipt.json", "plan.json", "candidate.sqlite3", "restored.sqlite3",
               "change-progress.json", "recovery-reference.json"}
    names = [entry["name"] for entry in receipt["files"]]
    if not names or len(names) != len(set(names)) or not set(names) <= allowed:
        raise ValueError("Invalid export file inventory")
    if {path.name for path in directory.iterdir()} != set(names) | {"receipt.json"}:
        raise ValueError("Export contains missing or stale files")
    for entry in receipt["files"]:
        path = directory / entry["name"]
        if path.is_symlink() or not path.is_file():
            raise ValueError("Invalid exported file: " + entry["name"])
        data = path.read_bytes()
        if len(data) != entry["byteCount"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Incomplete or concurrently replaced export: " + entry["name"])
    if "report.json" in names:
        report = json.loads((directory / "report.json").read_text())
        if any(report[key] != receipt[key] for key in ["sessionID", "appVersion", "appBuild"]):
            raise ValueError("Report and export build/session do not match")
        if "operation" in metadata and report.get("operation") != metadata["operation"]:
            raise ValueError("Report and session operation do not match")
        if report.get("operation") == "permissions":
            verify_access_report(report, names)
        if report.get("operation") in {"apply", "restore"}:
            verify_change_report(report, names, directory)
    if "baseline-receipt.json" in names:
        required = {"baseline.sqlite3", "baseline-report.json"}
        if not required <= set(names):
            raise ValueError("Incomplete recovery baseline artifacts; downloaded logs are preserved")
        baseline = json.loads((directory / "baseline-receipt.json").read_text())
        changing = report.get("operation") in {"apply", "restore"}
        expected_baseline_id = (json.loads((directory / "recovery-reference.json").read_text())["baselineID"]
                                if changing and "recovery-reference.json" in names else receipt["sessionID"])
        if (baseline["baselineFormatVersion"] != 1 or baseline["sessionID"] != expected_baseline_id
            or (not changing and any(baseline[key] != receipt[key] for key in ["appVersion", "appBuild"]))):
            raise ValueError("Recovery baseline build/session mismatch")
        entries = baseline["files"]
        if len(entries) != 2 or {entry["name"] for entry in entries} != required:
            raise ValueError("Invalid recovery baseline inventory")
        for entry in entries:
            data = (directory / entry["name"]).read_bytes()
            if len(data) != entry["byteCount"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("Recovery baseline fingerprint mismatch")
        baseline_report = json.loads((directory / "baseline-report.json").read_text())
        baseline_hash = hashlib.sha256((directory / "baseline.sqlite3").read_bytes()).hexdigest()
        if any(baseline_report[key] != baseline[key] for key in ["sessionID", "appVersion", "appBuild"]) or (
            baseline_report.get("status") != "complete"
            or baseline_report["database"] != baseline["database"]
            or baseline["database"]["snapshotSHA256"] != baseline_hash
        ):
            raise ValueError("Recovery baseline report mismatch")
    if "plan.json" in names:
        if not {"candidate.sqlite3", "restored.sqlite3", "baseline-receipt.json", "report.json"} <= set(names):
            raise ValueError("Incomplete offline preparation artifacts; downloaded logs are preserved")
        plan = json.loads((directory / "plan.json").read_text())
        if plan["planFormatVersion"] != 1 or any(
            plan[key] != baseline[key] for key in ["sessionID", "appVersion", "appBuild"]
        ):
            raise ValueError("Offline plan build/session mismatch")
        if (plan["baselineSHA256"] != baseline_hash
            or plan["activeDatabaseModified"] is not False
            or plan["logicalRestoreVerified"] is not True
            or plan["targetHosts"] != ["gs-loc.apple.com", "gs-loc-cn.apple.com"]
            or plan["originalRuleCount"] != baseline["database"]["ruleCount"]
            or plan["candidateRuleCount"] != plan["originalRuleCount"] - 1
            or any(plan["restoreRule"].get(key) != value for key, value in {
                "policyName": "AppleIssued", "domainSuffix": "apple.com",
                "labelRegex": "^gs-loc$|^gs-loc-cn$"
            }.items())
            or not (plan["restoreRule"].get("transparentConnection") is None
                    or (type(plan["restoreRule"]["transparentConnection"]) is int
                        and plan["restoreRule"]["transparentConnection"] == 0))
            or (report.get("preparation") or {}).get("offlinePlan") != plan):
            raise ValueError("Offline plan baseline/scope mismatch")
        for filename, key in [("candidate.sqlite3", "candidateSHA256"), ("restored.sqlite3", "restoredSHA256")]:
            if hashlib.sha256((directory / filename).read_bytes()).hexdigest() != plan[key]:
                raise ValueError("Offline plan database fingerprint mismatch")
        if any(len(match["rules"]) != 1 or match["rules"][0].get("sourceFingerprint") != plan["targetRuleFingerprint"]
               for match in baseline_report["hostMatches"]) or len(baseline_report["hostMatches"]) != 2:
            raise ValueError("Offline plan target fingerprint mismatch")
    print(f"Verified logs: version={receipt['appVersion']} build={receipt['appBuild']} session={receipt['sessionID']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["cleanup-packages", "verify-latest"])
    parser.add_argument("first")
    parser.add_argument("second", type=pathlib.Path)
    parser.add_argument("session", type=pathlib.Path, nargs="?")
    args = parser.parse_args()
    if args.operation == "cleanup-packages":
        cleanup_packages(args.first, args.second)
    else:
        if args.session is None:
            parser.error("verify-latest requires current-session.json")
        verify_latest(pathlib.Path(args.first), args.second, args.session)
