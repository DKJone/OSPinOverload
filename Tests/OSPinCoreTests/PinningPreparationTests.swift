import Foundation
import SQLite3
import XCTest
@testable import OSPinCore

final class PinningPreparationTests: XCTestCase {
    private var directory: URL!
    private var source: URL { directory.appendingPathComponent("source.sqlite3") }

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    }

    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }

    func testPreflightAcquiresAndRollsBackWithoutChangingSourceOrCreatingSidecars() throws {
        try fixture()
        let baseline = inspect()
        let before = try Data(contentsOf: source)
        let result = try preflight(baseline)
        XCTAssertEqual(result.report.status, .complete)
        XCTAssertEqual(result.report.operation, .prepare)
        XCTAssertEqual(result.report.preparation?.readWriteOpened, true)
        XCTAssertEqual(result.report.preparation?.transactionBegan, true)
        XCTAssertEqual(result.report.preparation?.rollbackSucceeded, true)
        XCTAssertEqual(result.report.preparation?.sourceUnchanged, true)
        XCTAssertEqual(result.report.preparation?.actualWriteCommitted, false)
        XCTAssertEqual(result.report.database.writeAccess, "not_tested")
        XCTAssertEqual(try Data(contentsOf: source), before)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["source.sqlite3"])
    }

    func testChangedBaselineStopsBeforeOpeningReadWrite() throws {
        try fixture()
        let baseline = inspect()
        try execute("UPDATE admin SET ival=132 WHERE key='version'")
        let before = try Data(contentsOf: source)
        let result = try preflight(baseline)
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNil(result.report.preparation?.readWriteOpened)
        XCTAssertEqual(result.report.preparation?.actualWriteCommitted, false)
        XCTAssertEqual(try Data(contentsOf: source), before)
    }

    func testHeldWriteLockFailsExplicitlyWithoutClaimingCommitCapability() throws {
        try fixture()
        let baseline = inspect()
        let database = try open()
        defer { sqlite3_close(database) }
        XCTAssertEqual(sqlite3_exec(database, "BEGIN IMMEDIATE", nil, nil, nil), SQLITE_OK)
        let result = try preflight(baseline)
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertEqual(result.report.preparation?.readWriteOpened, true)
        XCTAssertEqual(result.report.preparation?.transactionBegan, false)
        XCTAssertNil(result.report.preparation?.sourceUnchanged)
        XCTAssertTrue(result.report.checks.contains { $0.level == .fail && $0.detail.contains("SQLite (5)") })
        XCTAssertEqual(sqlite3_exec(database, "ROLLBACK", nil, nil, nil), SQLITE_OK)
    }

    func testWALAndExistingSidecarAreNotProbed() throws {
        try fixture()
        try Data().write(to: URL(fileURLWithPath: source.path + "-shm"))
        let sidecarResult = try preflight(inspect())
        XCTAssertEqual(sidecarResult.report.status, .failed)
        XCTAssertNil(sidecarResult.report.preparation?.readWriteOpened)
        try FileManager.default.removeItem(atPath: source.path + "-shm")
        let wal = try open()
        defer { sqlite3_close(wal) }
        XCTAssertEqual(sqlite3_exec(wal, "PRAGMA journal_mode=WAL; UPDATE admin SET ival=132 WHERE key='version'", nil, nil, nil), SQLITE_OK)
        let walResult = try preflight(inspect())
        XCTAssertEqual(walResult.report.database.journalMode, "wal")
        XCTAssertEqual(walResult.report.status, .failed)
        XCTAssertNil(walResult.report.preparation?.readWriteOpened)
    }

    func testNonRootPreparationDoesNotReadOrOpenWrite() throws {
        guard geteuid() != 0 else { throw XCTSkip("需要非 root 测试进程") }
        let result = PinningPreparation.preflight(
            path: source.path, sessionID: UUID(), baselineSHA256: String(repeating: "0", count: 64),
            baselineMetadataSHA256: String(repeating: "0", count: 64), log: { _ in }
        )
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNil(result.snapshot)
        XCTAssertNil(result.report.preparation?.readWriteOpened)
        XCTAssertFalse(FileManager.default.fileExists(atPath: source.path))
    }

    func testOfflineCandidatePreservesUnrelatedAppleIssuedRulesAndRestoresOriginalBlob() throws {
        try fixture()
        let envelope = inspect()
        let sourceBefore = try Data(contentsOf: source)
        let snapshot = try XCTUnwrap(envelope.snapshot)
        let planDirectory = directory.appendingPathComponent("plan")
        let plan = try PinningPreparation.createOfflinePlan(snapshot: snapshot, report: envelope.report, directory: planDirectory)
        XCTAssertEqual(plan.originalRuleCount, 3)
        XCTAssertEqual(plan.candidateRuleCount, 2)
        XCTAssertTrue(plan.logicalRestoreVerified)
        XCTAssertFalse(plan.activeDatabaseModified)
        XCTAssertEqual(plan.targetRuleFingerprint, envelope.report.hostMatches.first?.rules.first?.sourceFingerprint)
        let restored = DiagnosticEngine.inspect(path: planDirectory.appendingPathComponent("restored.sqlite3").path,
                                               sessionID: envelope.report.sessionID, requireRoot: false, log: { _ in })
        XCTAssertEqual(restored.report.hostMatches.first?.rules.first?.sourceFingerprint, plan.targetRuleFingerprint)
        let candidate = DiagnosticEngine.inspect(path: planDirectory.appendingPathComponent("candidate.sqlite3").path,
                                                sessionID: envelope.report.sessionID, requireRoot: false, log: { _ in })
        XCTAssertEqual(candidate.report.hostMatches.map { $0.rules.count }, [0, 0])
        XCTAssertEqual(candidate.report.database.contentVersion, 131)
        XCTAssertEqual(try Data(contentsOf: source), sourceBefore)
    }

    func testAmbiguousAndDuplicateRulesCannotProduceCandidate() throws {
        try fixture()
        try execute("INSERT INTO rules SELECT * FROM rules WHERE labelRegex='^gs-loc$|^gs-loc-cn$'")
        let envelope = inspect()
        XCTAssertThrowsError(try PinningPreparation.createOfflinePlan(
            snapshot: XCTUnwrap(envelope.snapshot), report: envelope.report, directory: directory.appendingPathComponent("duplicate")
        ))
        try execute("UPDATE rules SET labelRegex='^gs-loc.*$' WHERE labelRegex='^itunes$'")
        let ambiguous = inspect()
        XCTAssertThrowsError(try PinningPreparation.targetRule(in: ambiguous.report))
    }

    func testUnexpectedTriggerMutationFailsRestorePreparation() throws {
        try fixture()
        try execute("CREATE TRIGGER corrupt_other AFTER DELETE ON rules BEGIN UPDATE admin SET ival=132 WHERE key='version'; END")
        let envelope = inspect()
        let before = try Data(contentsOf: source)
        XCTAssertThrowsError(try PinningPreparation.createOfflinePlan(
            snapshot: XCTUnwrap(envelope.snapshot), report: envelope.report, directory: directory.appendingPathComponent("trigger")
        ))
        XCTAssertEqual(try Data(contentsOf: source), before)
    }

    func testSnapshotMismatchAndUnsupportedSchemaAreRejectedBeforeCandidateCreation() throws {
        try fixture()
        let envelope = inspect()
        let output = directory.appendingPathComponent("bad")
        XCTAssertThrowsError(try PinningPreparation.createOfflinePlan(snapshot: Data([1]), report: envelope.report, directory: output))
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path))
        try execute("PRAGMA user_version=4")
        let changed = inspect()
        XCTAssertThrowsError(try PinningPreparation.createOfflinePlan(snapshot: XCTUnwrap(changed.snapshot), report: changed.report, directory: output))
        XCTAssertNil(try preflight(changed).report.preparation?.readWriteOpened)
    }

    func testIndependentBaselineCannotBeOverwrittenAndSurvivesLatestReplacement() throws {
        try fixture()
        let envelope = inspect()
        let baseline = directory.appendingPathComponent("Baselines").appendingPathComponent(envelope.report.sessionID.uuidString)
        let receipt = try RecoveryBaselineStore.save(envelope, directory: baseline)
        XCTAssertEqual(receipt.database.posixPermissions, envelope.report.database.posixPermissions)
        XCTAssertEqual(receipt.database.ownerID, envelope.report.database.ownerID)
        let bytes = try Data(contentsOf: baseline.appendingPathComponent("baseline.sqlite3"))
        XCTAssertThrowsError(try RecoveryBaselineStore.save(envelope, directory: baseline))
        let session = directory.appendingPathComponent("session")
        try FileManager.default.createDirectory(at: session, withIntermediateDirectories: false)
        try Data("log".utf8).write(to: session.appendingPathComponent("app.log"))
        for _ in 1...2 {
            _ = try DiagnosticExporter.export(sessionID: envelope.report.sessionID, sourceDirectory: session,
                                              exportRoot: directory.appendingPathComponent("Exports"))
        }
        try RecoveryBaselineStore.verify(directory: baseline, sessionID: envelope.report.sessionID)
        XCTAssertEqual(try Data(contentsOf: baseline.appendingPathComponent("baseline.sqlite3")), bytes)
    }

    func testTamperedBaselineAndWrongSessionAreRejected() throws {
        try fixture()
        let envelope = inspect()
        let baseline = directory.appendingPathComponent("baseline")
        _ = try RecoveryBaselineStore.save(envelope, directory: baseline)
        XCTAssertThrowsError(try RecoveryBaselineStore.verify(directory: baseline, sessionID: UUID()))
        let snapshot = baseline.appendingPathComponent("baseline.sqlite3")
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: snapshot.path)
        try Data("corrupt".utf8).write(to: snapshot)
        XCTAssertThrowsError(try RecoveryBaselineStore.verify(directory: baseline, sessionID: envelope.report.sessionID))
    }

    func testWorkerArgumentsAcceptOnlyFixedModesAndStrictBaselineDigest() {
        let id = UUID()
        let hash = String(repeating: "a", count: 64)
        XCTAssertEqual(DiagnosticWorkerRequest.parse(["--prepare", id.uuidString, hash, hash]), .prepare(id, hash, hash))
        XCTAssertEqual(DiagnosticWorkerRequest.parse(["--diagnose", id.uuidString]), .diagnose(id))
        for arguments in [
            ["--prepare", id.uuidString], ["--prepare", id.uuidString, hash], ["--prepare", id.uuidString, "../source.sqlite3"],
            ["--prepare", id.uuidString, hash, "/tmp/other"], ["--apply", id.uuidString, hash],
            ["--diagnose", id.uuidString, hash], ["--prepare", "invalid", hash],
            ["--prepare", id.uuidString, String(repeating: "z", count: 64)]
        ] { XCTAssertNil(DiagnosticWorkerRequest.parse(arguments)) }
    }

    private func inspect() -> DiagnosticEnvelope {
        DiagnosticEngine.inspect(path: source.path, sessionID: UUID(), requireRoot: false, log: { _ in })
    }

    private func preflight(_ baseline: DiagnosticEnvelope) throws -> DiagnosticEnvelope {
        PinningPreparation.preflight(path: source.path, sessionID: baseline.report.sessionID,
                                     baselineSHA256: baseline.report.database.snapshotSHA256 ?? "missing",
                                     baselineMetadataSHA256: PinningPreparation.sha256(try DiagnosticEncoding.encoder().encode(baseline.report.database)),
                                     requireRoot: false, log: { _ in })
    }

    func testChangedOwnershipMetadataStopsBeforeWriteProbe() throws {
        try fixture()
        let baseline = inspect()
        try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: source.path)
        let result = try preflight(baseline)
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNil(result.report.preparation?.readWriteOpened)
        XCTAssertFalse(result.report.preparation?.actualWriteCommitted ?? true)
    }

    func testIdenticalFileReplacementAfterSnapshotStopsBeforeWriteProbe() throws {
        try fixture()
        let baseline = inspect()
        let bytes = try Data(contentsOf: source)
        var replaced = false
        var replacementFailure: Error?
        let result = PinningPreparation.preflight(
            path: source.path, sessionID: baseline.report.sessionID,
            baselineSHA256: try XCTUnwrap(baseline.report.database.snapshotSHA256),
            baselineMetadataSHA256: PinningPreparation.sha256(try DiagnosticEncoding.encoder().encode(baseline.report.database)),
            requireRoot: false
        ) { message in
            if message.hasPrefix("诊断结束"), !replaced {
                do { try bytes.write(to: self.source, options: .atomic); replaced = true }
                catch { replacementFailure = error }
            }
        }
        XCTAssertTrue(replaced)
        XCTAssertNil(replacementFailure)
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNil(result.report.preparation?.readWriteOpened)
    }

    func testOldOptionalReportFieldsRemainDecodableWithoutInventingFingerprints() throws {
        try fixture()
        let report = inspect().report
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: DiagnosticEncoding.encoder().encode(report)) as? [String: Any])
        object.removeValue(forKey: "operation")
        var matches = try XCTUnwrap(object["hostMatches"] as? [[String: Any]])
        for index in matches.indices {
            var rules = try XCTUnwrap(matches[index]["rules"] as? [[String: Any]])
            for rule in rules.indices { rules[rule].removeValue(forKey: "sourceFingerprint") }
            matches[index]["rules"] = rules
        }
        object["hostMatches"] = matches
        let decoded = try DiagnosticEncoding.decoder().decode(DiagnosticReport.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertNil(decoded.operation)
        XCTAssertNil(decoded.preparation)
        XCTAssertNil(decoded.hostMatches.first?.rules.first?.sourceFingerprint)
        XCTAssertThrowsError(try PinningPreparation.targetRule(in: decoded))
    }

    private func fixture() throws {
        let policies = try PropertyListSerialization.data(fromPropertyList: [["AnchorApple": true, "LeafMarkerOid": "owned-test"]],
                                                          format: .binary, options: 0)
        let hex = policies.map { String(format: "%02x", $0) }.joined()
        try execute("""
        PRAGMA user_version=3;
        CREATE TABLE admin(key TEXT PRIMARY KEY NOT NULL,ival INTEGER NOT NULL,value BLOB);
        INSERT INTO admin VALUES('version',131,X'00ff');
        INSERT INTO admin VALUES('opaque',-42,X'000102ff');
        CREATE TABLE rules(policyName TEXT,domainSuffix TEXT,labelRegex TEXT,policies BLOB,transparentConnection INTEGER);
        INSERT INTO rules VALUES('AppleIssued','apple.com','^gs-loc$|^gs-loc-cn$',X'\(hex)',0);
        INSERT INTO rules VALUES('AppleIssued','apple.com','^itunes$',X'\(hex)',NULL);
        INSERT INTO rules VALUES('Other','example.com','^other$',X'\(hex)',1);
        """)
    }

    private func open() throws -> OpaquePointer {
        var database: OpaquePointer?
        guard sqlite3_open(source.path, &database) == SQLITE_OK, let database else {
            if let database { sqlite3_close(database) }
            throw NSError(domain: "Fixture", code: 1)
        }
        return database
    }

    private func execute(_ sql: String) throws {
        let database = try open()
        defer { sqlite3_close(database) }
        guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
            throw NSError(domain: "Fixture", code: 2, userInfo: [NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(database))])
        }
    }
}
