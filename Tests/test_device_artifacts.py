import hashlib
import importlib.util
import json
import pathlib
import plistlib
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("device_artifacts", ROOT / "packaging/device_artifacts.py")
artifacts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifacts)


class DeviceArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temporary.name)
        self.info = ROOT / "Resources/Info.plist"
        info = plistlib.loads(self.info.read_bytes())
        self.metadata = dict(sessionID="current-session", appVersion=info["CFBundleShortVersionString"],
                             appBuild=info["CFBundleVersion"])
        self.current_session = self.directory / "current-session.json"
        self.current_session.write_text(json.dumps(self.metadata))
        self.latest = self.directory / "Latest"
        self.latest.mkdir()
        data = json.dumps(self.metadata).encode()
        (self.latest / "report.json").write_bytes(data)
        self.receipt = dict(self.metadata, receiptFormatVersion=1, files=[
            dict(name="report.json", byteCount=len(data), sha256=hashlib.sha256(data).hexdigest())
        ])
        self.write_receipt()

    def tearDown(self):
        self.temporary.cleanup()

    def write_receipt(self):
        (self.latest / "receipt.json").write_text(json.dumps(self.receipt))

    def verify(self):
        artifacts.verify_latest(self.latest, self.info, self.current_session)

    def test_valid_export(self):
        self.verify()

    def permission_fixture(self):
        self.current_session.write_text(json.dumps(dict(self.metadata, operation="permissions")))
        identity = dict(uid=501, effectiveUID=501, gid=20, effectiveGID=20, pid=123)
        report = dict(self.metadata, operation="permissions", status="failed",
                      database=dict(sourcePath="/private/var/protected/trustd/pinningrules.sqlite3", writeAccess="not_tested"),
                      accessProbes=[dict(profile=profile, identity=identity, identityVerified=False,
                                         status="failed", paths=[], runtimeEntitlement=dict(
                                             key="com.apple.private.security.storage.trustd", method="csops_self_xml",
                                             processID=123, state="unavailable", probeReturnValue=-1,
                                             probeErrno=1, detail="query denied"))
                                    for profile in ["root", "trustd"]],
                      accessFailures=[])
        self.add_file("report.json", report)
        return report

    def test_failed_permission_diagnostics_remain_downloadable(self):
        self.permission_fixture()
        self.verify()

    def test_partial_permission_comparison_preserves_spawn_failure(self):
        report = self.permission_fixture()
        report.update(status="partial", accessProbes=report["accessProbes"][:1],
                      accessFailures=[dict(profile="trustd", detail="spawn EPERM")])
        self.add_file("report.json", report)
        self.verify()

    def test_duplicate_permission_profiles_rejected(self):
        report = self.permission_fixture()
        report["accessProbes"][1]["profile"] = "root"
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "profiles"):
            self.verify()

    def test_permission_identity_mismatch_rejected(self):
        report = self.permission_fixture()
        report["accessProbes"][0]["identityVerified"] = True
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.verify()

    def test_permission_probe_cannot_touch_paths_before_identity_verification(self):
        report = self.permission_fixture()
        report["accessProbes"][0]["paths"] = [dict(path="/private/var/protected")]
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "before identity"):
            self.verify()

    def test_permission_export_cannot_include_old_snapshot(self):
        self.permission_fixture()
        self.add_file("pinningrules.snapshot.sqlite3", b"stale snapshot")
        with self.assertRaisesRegex(ValueError, "scope mismatch"):
            self.verify()

    def test_incomplete_permission_probe_cannot_claim_complete(self):
        report = self.permission_fixture()
        report["status"] = "complete"
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "probe claimed complete"):
            self.verify()

    def complete_permission_fixture(self, denied=False):
        report = self.permission_fixture()
        report["status"] = "complete"
        attributes = dict(deviceID=1, fileID=3, mode=0o100600, ownerID=282, groupID=282,
                          size=4096, flags=0, modifiedSeconds=1, modifiedNanoseconds=0,
                          changedSeconds=1, changedNanoseconds=0)
        paths = ["/private/var/protected", "/private/var/protected/trustd",
                 "/private/var/protected/trustd/pinningrules.sqlite3"]
        for probe in report["accessProbes"]:
            expected = 0 if probe["profile"] == "root" else 282
            probe.update(status="complete", identityVerified=True,
                         identity=dict(uid=expected, effectiveUID=expected, gid=expected, effectiveGID=expected, pid=123),
                         paths=[dict(path=path, statErrno=0, statfsErrno=0, attributes=attributes,
                                     mount=dict(flags=0, readOnly=False, filesystem="apfs", mountPoint="/private/var"))
                                for path in paths],
                         afterStatErrno=0, afterAttributes=attributes, sourceMetadataUnchanged=True,
                         open=dict(requestedFlags=0x01000106, returnValue=-1 if denied else 3,
                                   openErrno=13 if denied else 0))
            probe["runtimeEntitlement"].update(state="boolean", value=True, probeErrno=34,
                                               readReturnValue=0, readErrno=0, blobByteCount=256)
            if not denied:
                probe["open"].update(getFlagsReturnValue=6, getFlagsErrno=0, descriptorStatErrno=0,
                                     descriptorAttributes=attributes, descriptorMatchesSource=True,
                                     closeReturnValue=0, closeErrno=0)
        self.add_file("report.json", report)
        return report

    def test_complete_permission_open_evidence_is_verified(self):
        self.complete_permission_fixture()
        self.verify()

    def test_complete_permission_denial_evidence_is_verified(self):
        self.complete_permission_fixture(denied=True)
        self.verify()

    def test_complete_permission_denial_requires_raw_errno(self):
        report = self.complete_permission_fixture(denied=True)
        report["accessProbes"][1]["open"]["openErrno"] = 0
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "missing errno"):
            self.verify()

    def test_permission_descriptor_with_wrong_access_mode_is_rejected(self):
        report = self.complete_permission_fixture()
        report["accessProbes"][0]["open"]["getFlagsReturnValue"] = 0
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "descriptor not confirmed"):
            self.verify()

    def test_runtime_entitlement_query_failure_cannot_claim_true(self):
        report = self.permission_fixture()
        report["accessProbes"][0]["runtimeEntitlement"]["value"] = True
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "cannot claim a value"):
            self.verify()

    def test_runtime_entitlement_pid_must_match_worker(self):
        report = self.permission_fixture()
        report["accessProbes"][0]["runtimeEntitlement"]["processID"] = 999
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "runtime entitlement evidence"):
            self.verify()

    def test_complete_comparison_requires_runtime_entitlement_evidence(self):
        report = self.complete_permission_fixture()
        del report["accessProbes"][0]["runtimeEntitlement"]
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "runtime entitlement evidence"):
            self.verify()

    def test_runtime_false_is_valid_evidence_not_a_transport_failure(self):
        report = self.complete_permission_fixture(denied=True)
        report["accessProbes"][1]["runtimeEntitlement"]["value"] = False
        self.add_file("report.json", report)
        self.verify()

    def test_malformed_runtime_evidence_is_rejected_explicitly(self):
        cases = [
            ("evidence", None), ("evidence", []),
            ("state", []), ("state", {}),
            ("processID", None), ("processID", 0), ("processID", True),
            ("probeReturnValue", False), ("probeErrno", False),
            ("readReturnValue", False), ("readErrno", False),
            ("blobByteCount", None), ("blobByteCount", 256.5), ("blobByteCount", True),
            ("detail", {"unexpected": "object"}), ("detail", ""),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                report = self.complete_permission_fixture(denied=True)
                probe = report["accessProbes"][0]
                if field == "evidence":
                    probe["runtimeEntitlement"] = value
                else:
                    probe["runtimeEntitlement"][field] = value
                self.add_file("report.json", report)
                with self.assertRaisesRegex(ValueError, "runtime entitlement|kernel read"):
                    self.verify()

    def add_file(self, name, data):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        (self.latest / name).write_bytes(data)
        self.receipt["files"] = [entry for entry in self.receipt["files"] if entry["name"] != name]
        self.receipt["files"].append(dict(name=name, byteCount=len(data), sha256=hashlib.sha256(data).hexdigest()))
        self.write_receipt()

    def preparation_fixture(self):
        baseline_data, candidate_data, restored_data = b"baseline", b"candidate", b"restored"
        baseline_hash = hashlib.sha256(baseline_data).hexdigest()
        database = dict(snapshotSHA256=baseline_hash, snapshotByteCount=len(baseline_data), ruleCount=133)
        baseline_report = dict(self.metadata, status="complete", database=database, hostMatches=[
            dict(hostname=host, rules=[dict(sourceFingerprint="a" * 64)])
            for host in ["gs-loc.apple.com", "gs-loc-cn.apple.com"]
        ])
        self.add_file("baseline.sqlite3", baseline_data)
        self.add_file("baseline-report.json", baseline_report)
        baseline_entries = [dict(entry) for entry in self.receipt["files"] if entry["name"].startswith("baseline")]
        self.add_file("baseline-receipt.json", dict(self.metadata, baselineFormatVersion=1, database=database, files=baseline_entries))
        self.add_file("candidate.sqlite3", candidate_data)
        self.add_file("restored.sqlite3", restored_data)
        plan = dict(
            self.metadata, planFormatVersion=1, baselineSHA256=baseline_hash, originalRuleCount=133,
            candidateRuleCount=132, logicalRestoreVerified=True, activeDatabaseModified=False,
            targetHosts=["gs-loc.apple.com", "gs-loc-cn.apple.com"], targetRuleFingerprint="a" * 64,
            candidateSHA256=hashlib.sha256(candidate_data).hexdigest(),
            restoredSHA256=hashlib.sha256(restored_data).hexdigest(),
            restoreRule=dict(policyName="AppleIssued", domainSuffix="apple.com",
                             labelRegex="^gs-loc$|^gs-loc-cn$", transparentConnection=0)
        )
        self.add_file("plan.json", plan)
        self.add_file("report.json", dict(self.metadata, preparation=dict(offlinePlan=plan)))
        return plan

    def test_valid_preparation_export(self):
        self.preparation_fixture()
        self.verify()

    def test_null_transparent_flag_in_preparation_export(self):
        self.preparation_fixture()
        plan = json.loads((self.latest / "plan.json").read_text())
        plan["restoreRule"].pop("transparentConnection")
        self.add_file("plan.json", plan)
        report = json.loads((self.latest / "report.json").read_text())
        report["preparation"]["offlinePlan"] = plan
        self.add_file("report.json", report)
        self.verify()

    def test_enabled_transparent_flag_still_rejected(self):
        self.preparation_fixture()
        plan = json.loads((self.latest / "plan.json").read_text())
        plan["restoreRule"]["transparentConnection"] = 1
        self.add_file("plan.json", plan)
        report = json.loads((self.latest / "report.json").read_text())
        report["preparation"]["offlinePlan"] = plan
        self.add_file("report.json", report)
        with self.assertRaisesRegex(ValueError, "scope mismatch"):
            self.verify()

    def change_fixture(self, action="apply"):
        plan = self.preparation_fixture()
        if action == "restore":
            for name in ["plan.json", "candidate.sqlite3", "restored.sqlite3"]:
                (self.latest / name).unlink()
                self.receipt["files"] = [e for e in self.receipt["files"] if e["name"] != name]
            baseline_metadata = dict(self.metadata, sessionID="previous-baseline", appVersion="0.2.2", appBuild="6")
            baseline_report = json.loads((self.latest / "baseline-report.json").read_text())
            baseline_report.update(baseline_metadata)
            self.add_file("baseline-report.json", baseline_report)
            baseline = json.loads((self.latest / "baseline-receipt.json").read_text())
            baseline.update(baseline_metadata)
            baseline["files"] = [dict(e) for e in self.receipt["files"] if e["name"] in {"baseline.sqlite3", "baseline-report.json"}]
            self.add_file("baseline-receipt.json", baseline)
        baseline = json.loads((self.latest / "baseline-receipt.json").read_text())
        digest = hashlib.sha256((self.latest / "baseline-receipt.json").read_bytes()).hexdigest()
        change = dict(baselineID=baseline["sessionID"], baselineReceiptSHA256=digest, action=action,
                      commitState="committed", verified=True, alreadyRestored=False,
                      beforeRuleCount=133 if action == "apply" else 132, afterRuleCount=132 if action == "apply" else 133,
                      detail="verified one-row commit")
        self.add_file("recovery-reference.json", dict(baselineID=baseline["sessionID"], receiptSHA256=digest))
        self.add_file("change-progress.json", change)
        report = dict(self.metadata, operation=action, status="complete", change=change,
                      identity=dict(uid=0, effectiveUID=0, gid=0, effectiveGID=0),
                      database=dict(sourcePath="/private/var/protected/trustd/pinningrules.sqlite3",
                                    writeAccess="commit_succeeded", ruleCount=change["afterRuleCount"]))
        if action == "apply":
            report["preparation"] = dict(offlinePlan=plan)
        self.add_file("report.json", report)
        return report

    def save_change(self, report):
        self.add_file("report.json", report)
        self.add_file("change-progress.json", report["change"])

    def test_valid_committed_apply_export(self):
        self.change_fixture()
        self.verify()

    def test_valid_restore_from_previous_build_and_session(self):
        self.change_fixture("restore")
        self.verify()

    def test_unknown_commit_cannot_claim_complete(self):
        report = self.change_fixture()
        report["change"]["commitState"] = "unknown"
        self.save_change(report)
        with self.assertRaisesRegex(ValueError, "Unverified or unknown"):
            self.verify()

    def test_post_commit_failure_retains_committed_evidence(self):
        report = self.change_fixture()
        report["status"] = "failed"
        report["change"]["verified"] = False
        self.save_change(report)
        self.verify()

    def test_disagreeing_durable_progress_rejected(self):
        report = self.change_fixture()
        changed = dict(report["change"], commitState="unknown")
        self.add_file("change-progress.json", changed)
        with self.assertRaisesRegex(ValueError, "durable progress disagree"):
            self.verify()

    def test_change_recovery_hash_must_match_independent_baseline(self):
        report = self.change_fixture()
        self.add_file("recovery-reference.json", dict(
            baselineID=report["change"]["baselineID"], receiptSHA256="0" * 64))
        with self.assertRaisesRegex(ValueError, "recovery reference mismatch"):
            self.verify()

    def test_rule_change_row_count_is_exactly_one(self):
        report = self.change_fixture()
        report["change"]["afterRuleCount"] = 130
        self.save_change(report)
        with self.assertRaisesRegex(ValueError, "row-count scope"):
            self.verify()

    def test_verified_restore_noop_does_not_claim_commit(self):
        report = self.change_fixture("restore")
        report["change"].update(commitState="notAttempted", alreadyRestored=True, beforeRuleCount=133)
        report["database"]["writeAccess"] = "not_committed"
        self.save_change(report)
        self.verify()

    def test_failed_apply_before_baseline_remains_exportable(self):
        self.add_file("report.json", dict(self.metadata, operation="apply", status="failed",
                                         database=dict(sourcePath="/private/var/protected/trustd/pinningrules.sqlite3")))
        self.verify()

    def test_malformed_change_state_is_explicitly_rejected(self):
        report = self.change_fixture()
        report["change"]["commitState"] = []
        self.save_change(report)
        with self.assertRaisesRegex(ValueError, "Invalid rule change"):
            self.verify()

    def test_inner_baseline_fingerprint_rejects_rehashed_corruption(self):
        self.preparation_fixture()
        self.add_file("baseline.sqlite3", b"corrupted-but-outer-receipt-valid")
        with self.assertRaisesRegex(ValueError, "baseline fingerprint"):
            self.verify()

    def test_offline_candidate_fingerprint_rejects_rehashed_corruption(self):
        self.preparation_fixture()
        self.add_file("candidate.sqlite3", b"other")
        with self.assertRaisesRegex(ValueError, "plan database fingerprint"):
            self.verify()

    def test_plan_cannot_claim_active_system_modification(self):
        plan = self.preparation_fixture()
        plan["activeDatabaseModified"] = True
        self.add_file("plan.json", plan)
        with self.assertRaisesRegex(ValueError, "scope mismatch"):
            self.verify()

    def test_incomplete_preparation_preserves_error_but_is_not_verified(self):
        self.add_file("plan.json", {})
        with self.assertRaisesRegex(ValueError, "Incomplete offline preparation"):
            self.verify()
        self.assertTrue((self.latest / "report.json").exists())

    def test_baseline_session_mismatch_rejected(self):
        self.preparation_fixture()
        baseline = json.loads((self.latest / "baseline-receipt.json").read_text())
        baseline["sessionID"] = "old-session"
        self.add_file("baseline-receipt.json", baseline)
        with self.assertRaisesRegex(ValueError, "baseline build/session mismatch"):
            self.verify()

    def test_old_build_rejected(self):
        self.receipt["appBuild"] = "old"
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "older build"):
            self.verify()

    def test_old_session_rejected(self):
        self.current_session.write_text(json.dumps(dict(self.metadata, sessionID="newer-session")))
        with self.assertRaisesRegex(ValueError, "current diagnostic"):
            self.verify()

    def test_stale_snapshot_rejected(self):
        (self.latest / "pinningrules.snapshot.sqlite3").write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "stale files"):
            self.verify()

    def test_incomplete_file_rejected(self):
        (self.latest / "report.json").write_bytes(b"incomplete")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.verify()

    def test_path_traversal_rejected(self):
        self.receipt["files"][0]["name"] = "../report.json"
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.verify()

    def test_package_cleanup_targets_only_old_project_files(self):
        current = "OSPinOverload-0.1.2-build3-111111111111-222222222222.tipa"
        old = "OSPinOverload-0.1.1-333333333333-444444444444.tipa"
        receipt_path = self.directory / "transfer.json"
        receipt_path.write_text(json.dumps(dict(devicePath="/var/mobile/Media/" + current, readBackVerified=True)))
        with patch.object(artifacts, "afc", side_effect=[
            "afc:/ > " + current + "\n" + old + "\nOtherApp.tipa\nDownloads\n",
            'afc:/ > {"st_ifmt":"S_IFREG"}\nafc:/ > ',
            "",
            "afc:/ > " + current + "\nOtherApp.tipa\n",
        ]) as afc:
            artifacts.cleanup_packages("test-device", receipt_path)
            self.assertEqual(afc.call_args_list[2].args[1], ["rm " + old])
        receipt = json.loads(receipt_path.read_text())
        self.assertTrue(receipt["cleanupComplete"])
        self.assertEqual(receipt["removedPackages"], [old])

    def test_cleanup_never_runs_for_unverified_transfer(self):
        receipt_path = self.directory / "transfer.json"
        receipt_path.write_text(json.dumps(dict(devicePath="/var/mobile/Media/OSPinOverload.tipa", readBackVerified=False)))
        with patch.object(artifacts, "afc") as afc, self.assertRaises(ValueError):
            artifacts.cleanup_packages("test-device", receipt_path)
        afc.assert_not_called()

    def test_cleanup_does_not_delete_when_new_package_missing(self):
        receipt_path = self.directory / "transfer.json"
        receipt_path.write_text(json.dumps(dict(devicePath="/var/mobile/Media/OSPinOverload.tipa", readBackVerified=True)))
        with patch.object(artifacts, "afc", return_value="OtherApp.tipa") as afc, self.assertRaises(RuntimeError):
            artifacts.cleanup_packages("test-device", receipt_path)
        self.assertEqual(afc.call_count, 1)

    def test_cleanup_rejects_non_regular_packages(self):
        receipt_path = self.directory / "transfer.json"
        receipt_path.write_text(json.dumps(dict(devicePath="/var/mobile/Media/OSPinOverload.tipa", readBackVerified=True)))
        with patch.object(artifacts, "afc", side_effect=[
            "OSPinOverload.tipa\nOSPinOverload-0.1.1.tipa",
            '{"st_ifmt":"S_IFDIR"}',
        ]) as afc, self.assertRaisesRegex(RuntimeError, "non-regular"):
            artifacts.cleanup_packages("test-device", receipt_path)
        self.assertEqual(afc.call_count, 2)

    def test_unsafe_package_names_not_selected(self):
        self.assertEqual(artifacts.package_names("OtherApp.tipa\n../OSPinOverload.tipa\nOSPinOverload.tipa;rm x"), set())

    def test_afc_error_output_is_failure_even_with_zero_exit_code(self):
        log = self.directory / "cleanup.log"
        with patch.object(artifacts.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="Error: cannot remove")):
            with self.assertRaises(RuntimeError):
                artifacts.afc("test-device", ["ls"], log)
        self.assertIn("Error:", log.read_text())

    def test_incomplete_cleanup_does_not_mark_receipt_complete(self):
        receipt_path = self.directory / "transfer.json"
        receipt_path.write_text(json.dumps(dict(devicePath="/var/mobile/Media/OSPinOverload.tipa", readBackVerified=True, cleanupComplete=False)))
        listing = "OSPinOverload.tipa\nOSPinOverload-0.1.1.tipa"
        with patch.object(artifacts, "afc", side_effect=[listing, '{"st_ifmt":"S_IFREG"}', "", listing]):
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                artifacts.cleanup_packages("test-device", receipt_path)
        self.assertFalse(json.loads(receipt_path.read_text())["cleanupComplete"])


if __name__ == "__main__":
    unittest.main()
