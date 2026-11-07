import Foundation
import SQLite3
import XCTest
@testable import OSPinCore

final class ControlledRuleChangeTests: XCTestCase {
    private var directory: URL!
    private var source: URL { directory.appendingPathComponent("source.sqlite3") }
    private var baseline: URL { directory.appendingPathComponent("baseline") }
    private var reference: RuleRecoveryReference!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let plist = try PropertyListSerialization.data(fromPropertyList: [["ChainLength": 3]], format: .xml, options: 0)
        let blob = plist.map { String(format: "%02x", $0) }.joined()
        try sql("""
        PRAGMA user_version=3;
        CREATE TABLE admin(key TEXT PRIMARY KEY NOT NULL,ival INTEGER NOT NULL,value BLOB);
        INSERT INTO admin VALUES('version',131,NULL);
        CREATE TABLE rules(policyName TEXT NOT NULL,domainSuffix TEXT NOT NULL,labelRegex TEXT NOT NULL,policies BLOB NOT NULL,transparentConnection INTEGER,UNIQUE(policyName,domainSuffix,labelRegex));
        INSERT INTO rules(rowid,policyName,domainSuffix,labelRegex,policies,transparentConnection) VALUES(42,'AppleIssued','apple.com','^gs-loc$|^gs-loc-cn$',X'\(blob)',0);
        INSERT INTO rules VALUES('AppleIssued','apple.com','^itunes$',X'\(blob)',0);
        INSERT INTO rules VALUES('Other','example.com','.*',X'\(blob)',NULL);
        """)
        let envelope = DiagnosticEngine.inspect(path: source.path, sessionID: UUID(), requireRoot: false, log: { _ in })
        XCTAssertEqual(envelope.report.status, .complete)
        _ = try RecoveryBaselineStore.save(envelope, directory: baseline)
        reference = RuleRecoveryReference(baselineID: envelope.report.sessionID, receiptSHA256: PinningPreparation.sha256(
            try Data(contentsOf: baseline.appendingPathComponent("baseline-receipt.json"))
        ))
    }

    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }

    private func run(_ action: DiagnosticOperation, persist: (RuleChangeResult) throws -> Void = { _ in }) -> DiagnosticEnvelope {
        ControlledRuleChange.run(action: action, sessionID: UUID(), reference: reference,
                                 baselineDirectory: baseline, path: source.path, requireRoot: false, persist: persist, log: { _ in })
    }

    private func sql(_ text: String) throws {
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(source.path, &db), SQLITE_OK)
        defer { sqlite3_close(db) }
        let code = sqlite3_exec(db, text, nil, nil, nil)
        guard code == SQLITE_OK else { throw PinningPreparation.failure("fixture SQL \(code)") }
    }

    private func state(_ path: String) throws -> [String] {
        let db = try PreparationDatabase(path: path, writable: false)
        return try db.rows("SELECT rowid,* FROM rules") + db.rows("SELECT rowid,* FROM admin")
    }

    func testApplyAndRestoreCommitExactlyOneRowIncludingOriginalRowIDAndBlob() throws {
        let original = try state(source.path)
        var states: [RuleCommitState] = []
        let apply = run(.apply) { states.append($0.commitState) }
        XCTAssertEqual(apply.report.status, .complete, DiagnosticSummary.text(apply.report))
        XCTAssertEqual(apply.report.change?.commitState, .committed)
        XCTAssertEqual(apply.report.change?.verified, true)
        XCTAssertEqual(apply.report.database.ruleCount, 2)
        XCTAssertEqual(apply.report.database.writeAccess, "commit_succeeded")
        XCTAssertTrue(states.contains(.committing))
        XCTAssertTrue(states.contains(.committed))
        XCTAssertEqual(try state(source.path).count, original.count - 1)
        let restored = run(.restore)
        XCTAssertEqual(restored.report.status, .complete, DiagnosticSummary.text(restored.report))
        XCTAssertEqual(restored.report.change?.verified, true)
        XCTAssertEqual(restored.report.change?.commitState, .committed)
        XCTAssertEqual(try state(source.path), original)
        let again = run(.restore)
        XCTAssertEqual(again.report.status, .complete)
        XCTAssertEqual(again.report.change?.alreadyRestored, true)
        XCTAssertEqual(again.report.change?.commitState, .notAttempted)
    }

    func testRepeatApplyIsRejectedWithoutSecondDeletion() throws {
        XCTAssertEqual(run(.apply).report.status, .complete)
        let before = try state(source.path)
        let again = run(.apply)
        XCTAssertEqual(again.report.status, .failed)
        XCTAssertNotEqual(again.report.change?.commitState, .committed)
        XCTAssertEqual(try state(source.path), before)
    }

    func testSystemUpdateRefusesApplyAndRestoreRatherThanOverwriting() throws {
        try sql("UPDATE admin SET ival=132")
        let changed = try state(source.path)
        XCTAssertEqual(run(.apply).report.status, .failed)
        XCTAssertEqual(run(.restore).report.status, .failed)
        XCTAssertEqual(try state(source.path), changed)
    }

    func testChangedUnrelatedRuleAfterApplyBlocksRestore() throws {
        XCTAssertEqual(run(.apply).report.status, .complete)
        try sql("UPDATE rules SET transparentConnection=1 WHERE policyName='Other'")
        let changed = try state(source.path)
        XCTAssertEqual(run(.restore).report.status, .failed)
        XCTAssertEqual(try state(source.path), changed)
    }

    private func simulatePreviousMount() throws {
        var report = try DiagnosticEncoding.decoder().decode(
            DiagnosticReport.self, from: Data(contentsOf: baseline.appendingPathComponent("baseline-report.json"))
        )
        report.database.deviceID = try XCTUnwrap(report.database.deviceID) ^ 2
        let snapshot = try Data(contentsOf: baseline.appendingPathComponent("baseline.sqlite3"))
        try FileManager.default.removeItem(at: baseline)
        _ = try RecoveryBaselineStore.save(DiagnosticEnvelope(report: report, snapshot: snapshot), directory: baseline)
        reference = RuleRecoveryReference(baselineID: report.sessionID, receiptSHA256: PinningPreparation.sha256(
            try Data(contentsOf: baseline.appendingPathComponent("baseline-receipt.json"))
        ))
    }

    func testRestoreAfterRemountAcceptsOnlyDeviceNumberDrift() throws {
        let original = try state(source.path)
        XCTAssertEqual(run(.apply).report.status, .complete)
        try simulatePreviousMount()
        let restored = run(.restore)
        XCTAssertEqual(restored.report.status, .complete, DiagnosticSummary.text(restored.report))
        XCTAssertEqual(restored.report.change?.commitState, .committed)
        XCTAssertEqual(restored.report.change?.verified, true)
        XCTAssertEqual(try state(source.path), original)
        XCTAssertEqual(run(.restore).report.change?.alreadyRestored, true)
    }

    func testApplyDoesNotAcceptDeviceNumberDrift() throws {
        try simulatePreviousMount()
        let original = try Data(contentsOf: source)
        XCTAssertEqual(run(.apply).report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: source), original)
    }

    func testRemountedRestoreStillRefusesReplacementAndSidecars() throws {
        XCTAssertEqual(run(.apply).report.status, .complete)
        try simulatePreviousMount()
        let original = try Data(contentsOf: source)
        let journal = URL(fileURLWithPath: source.path + "-journal")
        try Data().write(to: journal)
        XCTAssertEqual(run(.restore).report.status, .failed)
        try FileManager.default.removeItem(at: journal)
        let alias = directory.appendingPathComponent("alias.sqlite3")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: source)
        let linked = ControlledRuleChange.run(
            action: .restore, sessionID: UUID(), reference: reference, baselineDirectory: baseline,
            path: alias.path, requireRoot: false, persist: { _ in }, log: { _ in }
        )
        XCTAssertEqual(linked.report.status, .failed)
        try original.write(to: source, options: .atomic)
        XCTAssertEqual(run(.restore).report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: source), original)
    }

    func testRemountedRestoreStillRefusesPermissionsAndUnrelatedDataChanges() throws {
        XCTAssertEqual(run(.apply).report.status, .complete)
        try simulatePreviousMount()
        let attributes = try FileManager.default.attributesOfItem(atPath: source.path)
        let permissions = try XCTUnwrap(attributes[.posixPermissions] as? NSNumber)
        let original = try Data(contentsOf: source)
        try FileManager.default.setAttributes([.posixPermissions: permissions.intValue ^ 0o040], ofItemAtPath: source.path)
        XCTAssertEqual(run(.restore).report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: source), original)
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: source.path)
        try sql("UPDATE admin SET ival=132; UPDATE rules SET transparentConnection=1 WHERE policyName='Other'")
        let changed = try state(source.path)
        XCTAssertEqual(run(.restore).report.status, .failed)
        XCTAssertEqual(try state(source.path), changed)
    }

    func testPersistenceFailureBeforeCommitRollsBackAndDoesNotClaimSuccess() throws {
        let before = try state(source.path)
        let result = run(.apply) {
            if $0.commitState == .committing { throw PinningPreparation.failure("test progress disk failure") }
        }
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNotEqual(result.report.change?.commitState, .committed)
        XCTAssertFalse(result.report.change?.verified ?? true)
        XCTAssertEqual(try state(source.path), before)
    }

    func testFailureAfterCommitPreservesCommittedButUnverifiedOutcomeForRecovery() throws {
        var injected = false
        let result = run(.apply) {
            if $0.commitState == .committed && !injected {
                injected = true
                throw PinningPreparation.failure("test crash after COMMIT")
            }
        }
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertEqual(result.report.change?.commitState, .committed)
        XCTAssertEqual(result.report.change?.verified, false)
        XCTAssertEqual(result.report.database.writeAccess, "commit_succeeded")
        XCTAssertEqual(run(.restore).report.status, .complete)
        XCTAssertEqual(try state(source.path), try state(baseline.appendingPathComponent("baseline.sqlite3").path))
    }

    func testReplacedFileSymlinkAndJournalAreRefused() throws {
        let before = try Data(contentsOf: source)
        try Data().write(to: URL(fileURLWithPath: source.path + "-journal"))
        XCTAssertEqual(run(.apply).report.status, .failed)
        try FileManager.default.removeItem(atPath: source.path + "-journal")
        try before.write(to: source, options: .atomic)
        XCTAssertEqual(run(.apply).report.status, .failed)
        let alias = directory.appendingPathComponent("alias.sqlite3")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: source)
        let result = ControlledRuleChange.run(
            action: .apply, sessionID: UUID(), reference: reference, baselineDirectory: baseline,
            path: alias.path, requireRoot: false, persist: { _ in }, log: { _ in }
        )
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: source), before)
    }

    func testTamperedReceiptAndTriggerAreRefused() throws {
        reference = RuleRecoveryReference(baselineID: reference.baselineID, receiptSHA256: String(repeating: "0", count: 64))
        XCTAssertEqual(run(.apply).report.status, .failed)
        reference = RuleRecoveryReference(baselineID: reference.baselineID, receiptSHA256: PinningPreparation.sha256(
            try Data(contentsOf: baseline.appendingPathComponent("baseline-receipt.json"))
        ))
        try sql("CREATE TRIGGER unexpected AFTER DELETE ON rules BEGIN DELETE FROM admin; END")
        let before = try Data(contentsOf: source)
        XCTAssertEqual(run(.apply).report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: source), before)
    }

    func testRootGatePrecedesBaselineAndSourceAccess() {
        guard geteuid() != 0 else { return }
        var persisted = false
        let result = ControlledRuleChange.run(
            action: .apply, sessionID: UUID(), reference: reference,
            baselineDirectory: directory.appendingPathComponent("missing"), path: "/nonexistent/source",
            persist: { _ in persisted = true }, log: { _ in }
        )
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertEqual(result.report.change?.commitState, .notAttempted)
        XCTAssertNil(result.snapshot)
        XCTAssertFalse(persisted)
    }

    func testBusyWriterIsNotBypassedAndNoCommitIsClaimed() throws {
        let held = try PreparationDatabase(path: source.path, writable: true)
        try held.execute("BEGIN IMMEDIATE")
        let result = run(.apply)
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertEqual(result.report.change?.commitState, .notAttempted)
        XCTAssertEqual(result.report.change?.verified, false)
        try held.execute("ROLLBACK")
        XCTAssertEqual(try state(source.path), try state(baseline.appendingPathComponent("baseline.sqlite3").path))
    }

    func testFixedWorkerArgumentsRejectPathsAndUnrecognizedActions() {
        let id = UUID(), baselineID = UUID(), hash = String(repeating: "a", count: 64)
        XCTAssertEqual(DiagnosticWorkerRequest.parse(["--apply", id.uuidString, baselineID.uuidString, hash]),
                       .change(id, .apply, baselineID, hash))
        XCTAssertEqual(DiagnosticWorkerRequest.parse(["--restore", id.uuidString, baselineID.uuidString, hash]),
                       .change(id, .restore, baselineID, hash))
        for args in [
            ["--apply", id.uuidString, "/tmp/db", hash], ["--apply", id.uuidString, baselineID.uuidString, "bad"],
            ["--restore", id.uuidString, baselineID.uuidString, hash, "extra"], ["--delete", id.uuidString, baselineID.uuidString, hash]
        ] { XCTAssertNil(DiagnosticWorkerRequest.parse(args)) }
    }

    private func refreshBaseline() throws {
        try FileManager.default.removeItem(at: baseline)
        let envelope = DiagnosticEngine.inspect(path: source.path, sessionID: UUID(), requireRoot: false, log: { _ in })
        XCTAssertEqual(envelope.report.status, .complete)
        _ = try RecoveryBaselineStore.save(envelope, directory: baseline)
        reference = RuleRecoveryReference(baselineID: envelope.report.sessionID, receiptSHA256: PinningPreparation.sha256(
            try Data(contentsOf: baseline.appendingPathComponent("baseline-receipt.json"))
        ))
    }

    func testColumnOrderContentVersionAndRuleCountAreNotHardcoded() throws {
        try sql("""
        ALTER TABLE rules RENAME TO previous_rules;
        CREATE TABLE rules(policies BLOB NOT NULL,labelRegex TEXT NOT NULL,transparentConnection INTEGER,domainSuffix TEXT NOT NULL,policyName TEXT NOT NULL,UNIQUE(policyName,domainSuffix,labelRegex));
        INSERT INTO rules(rowid,policyName,domainSuffix,labelRegex,policies,transparentConnection)
          SELECT rowid,policyName,domainSuffix,labelRegex,policies,transparentConnection FROM previous_rules;
        DROP TABLE previous_rules;
        UPDATE admin SET ival=999;
        INSERT INTO rules(policyName,domainSuffix,labelRegex,policies,transparentConnection)
          SELECT 'OtherTwo',domainSuffix,labelRegex,policies,transparentConnection FROM rules WHERE policyName='Other';
        """)
        try refreshBaseline()
        let original = try state(source.path)
        XCTAssertEqual(run(.apply).report.status, .complete)
        XCTAssertEqual(run(.restore).report.status, .complete)
        XCTAssertEqual(try state(source.path), original)
    }

    func testNullTransparentFlagAndOfflineRehearsalPreserveOriginalRowID() throws {
        try sql("UPDATE rules SET transparentConnection=NULL WHERE labelRegex='^gs-loc$|^gs-loc-cn$'")
        try refreshBaseline()
        let envelope = DiagnosticEngine.inspect(path: source.path, sessionID: UUID(), requireRoot: false, log: { _ in })
        _ = try PinningPreparation.createOfflinePlan(snapshot: XCTUnwrap(envelope.snapshot), report: envelope.report,
                                                   directory: directory.appendingPathComponent("plan"))
        let restored = try PreparationDatabase(path: directory.appendingPathComponent("plan/restored.sqlite3").path, writable: false)
        XCTAssertEqual(try restored.targetRowID(), 42)
        let original = try state(source.path)
        XCTAssertEqual(run(.apply).report.status, .complete)
        XCTAssertEqual(run(.restore).report.status, .complete)
        XCTAssertEqual(try state(source.path), original)
    }

    func testUnknownSchemaAndAdditionalRuleColumnRemainSafelyUnsupported() throws {
        try sql("PRAGMA user_version=999")
        try refreshBaseline()
        var original = try Data(contentsOf: source)
        XCTAssertEqual(run(.apply).report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: source), original)
        try sql("PRAGMA user_version=3; ALTER TABLE rules ADD COLUMN futureValue BLOB")
        try refreshBaseline()
        original = try Data(contentsOf: source)
        XCTAssertEqual(run(.apply).report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: source), original)
    }

    func testVersionOneRestoresAnInternallyConsistentBuildSevenBaseline() throws {
        let original = try state(source.path)
        XCTAssertEqual(run(.apply).report.status, .complete)
        let reportURL = baseline.appendingPathComponent("baseline-report.json")
        let receiptURL = baseline.appendingPathComponent("baseline-receipt.json")
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: reportURL.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: receiptURL.path)
        var oldReport = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: reportURL)) as? [String: Any])
        oldReport["appVersion"] = "0.3.0"
        oldReport["appBuild"] = "7"
        let oldBytes = try JSONSerialization.data(withJSONObject: oldReport, options: [.sortedKeys])
        try oldBytes.write(to: reportURL)
        var oldReceipt = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: receiptURL)) as? [String: Any])
        oldReceipt["appVersion"] = "0.3.0"
        oldReceipt["appBuild"] = "7"
        var files = try XCTUnwrap(oldReceipt["files"] as? [[String: Any]])
        let index = try XCTUnwrap(files.firstIndex { ($0["name"] as? String) == "baseline-report.json" })
        files[index]["byteCount"] = oldBytes.count
        files[index]["sha256"] = PinningPreparation.sha256(oldBytes)
        oldReceipt["files"] = files
        try JSONSerialization.data(withJSONObject: oldReceipt, options: [.sortedKeys]).write(to: receiptURL)
        reference = RuleRecoveryReference(baselineID: reference.baselineID, receiptSHA256: PinningPreparation.sha256(try Data(contentsOf: receiptURL)))
        XCTAssertEqual(run(.restore).report.status, .complete)
        XCTAssertEqual(try state(source.path), original)
    }
}
