import CryptoKit
import Foundation
import SQLite3
import XCTest
@testable import OSPinCore

final class DiagnosticTests: XCTestCase {
    private var directory: URL!
    private var databaseURL: URL { directory.appendingPathComponent("pinning.sqlite3") }

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    func testMatchesExactHostsAndPreservesPolicyDataWithoutChangingSource() throws {
        let database = try fixture()
        sqlite3_close(database)
        let before = try Data(contentsOf: databaseURL)
        let capture = try SQLitePinningReader().capture(
            path: databaseURL.path,
            hosts: ["gs-loc.apple.com", "gs-loc-cn.apple.com", "GS-LOC.apple.com.", "not-gs-loc.apple.com"],
            log: { _ in }
        )
        XCTAssertEqual(capture.schemaVersion, 3)
        XCTAssertEqual(capture.contentVersion, 131)
        XCTAssertEqual(capture.ruleCount, 2)
        XCTAssertEqual(capture.matches.map { $0.rules.count }, [1, 1, 1, 0])
        let rule = try XCTUnwrap(capture.matches.first?.rules.first)
        XCTAssertEqual(rule.policyName, "AppleIssued")
        XCTAssertEqual(rule.transparentConnection, 0)
        let policies = try PropertyListSerialization.propertyList(
            from: Data(rule.policiesPropertyListXML.utf8), options: [], format: nil
        ) as? [[String: Any]]
        XCTAssertEqual(policies?.first?["AnchorSHA256"] as? [Data], [Data([0x12, 0x34])])
        XCTAssertTrue(rule.policiesJSON.contains("1234"))
        XCTAssertEqual(try Data(contentsOf: databaseURL), before, "源数据库字节必须保持不变")
        let snapshotURL = directory.appendingPathComponent("snapshot.sqlite3")
        try capture.snapshot.write(to: snapshotURL)
        var snapshot: OpaquePointer?
        XCTAssertEqual(sqlite3_open_v2(snapshotURL.path, &snapshot, SQLITE_OPEN_READONLY, nil), SQLITE_OK)
        defer { sqlite3_close(snapshot) }
        XCTAssertEqual(try scalar(try XCTUnwrap(snapshot), "SELECT count(*) FROM rules"), 2)
    }

    func testBackupIncludesUncheckpointedWAL() throws {
        let database = try fixture()
        defer { sqlite3_close(database) }
        try execute(database, "PRAGMA journal_mode=WAL")
        try execute(database, "PRAGMA wal_autocheckpoint=0")
        try execute(database, "UPDATE admin SET ival=132 WHERE key='version'")
        XCTAssertTrue(FileManager.default.fileExists(atPath: databaseURL.path + "-wal"))
        let capture = try SQLitePinningReader().capture(path: databaseURL.path, hosts: DiagnosticEngine.targetHosts, log: { _ in })
        XCTAssertEqual(capture.contentVersion, 132)
        XCTAssertEqual(capture.journalMode, "wal")
        XCTAssertEqual(try scalar(database, "SELECT ival FROM admin WHERE key='version'"), 132)
    }

    func testSnapshotLimitIsEnforced() throws {
        let database = try fixture()
        sqlite3_close(database)
        XCTAssertThrowsError(
            try SQLitePinningReader(maximumSnapshotBytes: 1)
                .capture(path: databaseURL.path, hosts: DiagnosticEngine.targetHosts, log: { _ in })
        ) {
            XCTAssertEqual($0.localizedDescription, PinningReaderError.snapshotTooLarge.localizedDescription)
        }
    }

    func testMissingDatabaseProducesFailedReportWithoutCreatingSource() {
        let result = DiagnosticEngine.inspect(path: databaseURL.path, sessionID: UUID(), requireRoot: false, log: { _ in })
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNil(result.snapshot)
        XCTAssertTrue(result.report.checks.contains { $0.level == .fail })
        XCTAssertFalse(FileManager.default.fileExists(atPath: databaseURL.path))
        XCTAssertEqual(result.report.database.writeAccess, "not_tested")
    }

    func testMalformedPoliciesProduceExplicitFailure() throws {
        let database = try fixture()
        try execute(database, "UPDATE rules SET policies=X'010203' WHERE policyName='AppleIssued'")
        sqlite3_close(database)
        var logs: [String] = []
        let result = DiagnosticEngine.inspect(
            path: databaseURL.path, sessionID: UUID(), requireRoot: false, log: { logs.append($0) }
        )
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNil(result.snapshot)
        XCTAssertTrue(logs.contains { $0.contains("ERROR") })
    }

    func testMissingHostnameRulesProducePartialNotComplete() throws {
        let database = try fixture(pattern: "^something-else$")
        sqlite3_close(database)
        let result = DiagnosticEngine.inspect(path: databaseURL.path, sessionID: UUID(), requireRoot: false, log: { _ in })
        XCTAssertEqual(result.report.status, .partial)
        XCTAssertNotNil(result.snapshot)
        XCTAssertEqual(result.report.hostMatches.map { $0.rules.count }, [0, 0])
    }

    func testNonRootWorkerRefusesProtectedRead() throws {
        guard geteuid() != 0 else { throw XCTSkip("需要非 root 测试进程") }
        let database = try fixture()
        sqlite3_close(database)
        let result = DiagnosticEngine.inspect(path: databaseURL.path, sessionID: UUID(), requireRoot: true, log: { _ in })
        XCTAssertEqual(result.report.status, .failed)
        XCTAssertNil(result.snapshot)
        XCTAssertNil(result.report.database.schemaVersion)
        XCTAssertTrue(result.report.checks.contains { $0.name == "root_identity" && $0.level == .fail })
    }

    func testReportEncodingRoundTripAndHash() throws {
        let database = try fixture()
        sqlite3_close(database)
        let id = UUID()
        let result = DiagnosticEngine.inspect(path: databaseURL.path, sessionID: id, requireRoot: false, log: { _ in })
        XCTAssertEqual(result.report.status, .complete)
        let encoded = try DiagnosticEncoding.encoder().encode(result)
        let decoded = try DiagnosticEncoding.decoder().decode(DiagnosticEnvelope.self, from: encoded)
        XCTAssertEqual(decoded.report.sessionID, id)
        XCTAssertEqual(decoded.snapshot, result.snapshot)
        let snapshot = try XCTUnwrap(decoded.snapshot)
        XCTAssertEqual(decoded.report.database.snapshotByteCount, snapshot.count)
        XCTAssertEqual(
            decoded.report.database.snapshotSHA256,
            SHA256.hash(data: snapshot).map { String(format: "%02x", $0) }.joined()
        )
        XCTAssertTrue(DiagnosticSummary.text(decoded.report).contains("实际写入提交: 未测试"))
    }

    func testInvalidSchemaAndRegexAreReported() throws {
        let database = try fixture(pattern: "[")
        defer { sqlite3_close(database) }
        let invalidRegex = DiagnosticEngine.inspect(path: databaseURL.path, sessionID: UUID(), requireRoot: false, log: { _ in })
        XCTAssertEqual(invalidRegex.report.status, .failed)
        try execute(database, "DROP TABLE rules")
        let invalidSchema = DiagnosticEngine.inspect(path: databaseURL.path, sessionID: UUID(), requireRoot: false, log: { _ in })
        XCTAssertEqual(invalidSchema.report.status, .failed)
        XCTAssertTrue(invalidSchema.report.checks.contains { $0.detail.contains("no such table") })
    }

    private func fixture(pattern: String = "^gs-loc$|^gs-loc-cn$") throws -> OpaquePointer {
        var database: OpaquePointer?
        guard sqlite3_open(databaseURL.path, &database) == SQLITE_OK, let database else {
            throw NSError(domain: "Fixture", code: 1)
        }
        do {
            try execute(database, """
            PRAGMA user_version=3;
            CREATE TABLE admin(key TEXT PRIMARY KEY,ival INTEGER NOT NULL,value BLOB);
            INSERT INTO admin(key,ival) VALUES('version',131);
            CREATE TABLE rules(policyName TEXT,domainSuffix TEXT,labelRegex TEXT,policies BLOB,transparentConnection INTEGER);
            """)
            let policies: [[String: Any]] = [
                ["AnchorSHA256": [Data([0x12, 0x34])], "ChainLength": 3,
                 "CheckLeafMarkerOid": ["1.2.840.113635.100.6.86", "1.2.840.113635.100.6.87"]]
            ]
            let blob = try PropertyListSerialization.data(fromPropertyList: policies, format: .binary, options: 0)
            let hex = blob.map { String(format: "%02x", $0) }.joined()
            try execute(database, """
            INSERT INTO rules VALUES('AppleIssued','apple.com','\(pattern)',X'\(hex)',0);
            INSERT INTO rules VALUES('Other','example.com','^gs-loc$',X'\(hex)',1);
            """)
            return database
        } catch {
            sqlite3_close(database)
            throw error
        }
    }

    private func execute(_ database: OpaquePointer, _ sql: String) throws {
        if sqlite3_exec(database, sql, nil, nil, nil) != SQLITE_OK {
            throw NSError(domain: "Fixture", code: 2, userInfo: [
                NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(database))
            ])
        }
    }

    private func scalar(_ database: OpaquePointer, _ sql: String) throws -> Int64 {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK else {
            throw NSError(domain: "Fixture", code: 3)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw NSError(domain: "Fixture", code: 4) }
        return sqlite3_column_int64(statement, 0)
    }
}
