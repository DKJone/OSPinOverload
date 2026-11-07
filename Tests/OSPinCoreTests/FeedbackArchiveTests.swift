import Foundation
import XCTest
@testable import OSPinCore

final class FeedbackArchiveTests: XCTestCase {
    func testFilenameIncludesAppVersionUTCExportTimeAndShortRandomSuffix() throws {
        let id = try XCTUnwrap(UUID(uuidString: "ABCDEF12-3456-7890-ABCD-1234567890AB"))
        let name = FeedbackArchive.filename(date: Date(timeIntervalSince1970: 0), identifier: id)
        XCTAssertEqual(name, "OSPinOverload-feedback-v\(DiagnosticAppVersion.current)-19700101-000000Z-ABCDEF12.zip")
        XCTAssertFalse(name.contains(id.uuidString))
        XCTAssertEqual(URL(fileURLWithPath: name).lastPathComponent, name)
        XCTAssertEqual(URL(fileURLWithPath: name).pathExtension, "zip")
    }

    func testFilenamesRemainDistinctForExportsAtTheSameTime() throws {
        let first = try XCTUnwrap(UUID(uuidString: "ABCDEF12-3456-7890-ABCD-1234567890AB"))
        let second = try XCTUnwrap(UUID(uuidString: "12345678-3456-7890-ABCD-1234567890AB"))
        let date = Date(timeIntervalSince1970: 0)
        XCTAssertNotEqual(FeedbackArchive.filename(date: date, identifier: first),
                          FeedbackArchive.filename(date: date, identifier: second))
    }

    func testAllowlistExcludesRawDetailsPoliciesIdentifiersAndLogPayloads() throws {
        let seed = DiagnosticEngine.initialReport(sessionID: UUID(), path: "/private/SECRET_SOURCE")
        var report = DiagnosticReport(
            reportFormatVersion: seed.reportFormatVersion, appVersion: "1.0.0", appBuild: "8",
            sessionID: seed.sessionID, startedAt: seed.startedAt, finishedAt: seed.finishedAt,
            status: .failed, identity: seed.identity,
            device: DeviceInformation(machine: "iPhone12,1", systemVersion: "15.7.1", systemBuild: "19H117"),
            database: seed.database,
            checks: [.init(name: "root_identity", level: .fail, detail: "SECRET_COORDINATES"),
                     .init(name: "SECRET_CHECK", level: .warning, detail: "SECRET_MAC")],
            hostMatches: [.init(hostname: "SECRET_HOST", rules: [
                .init(policyName: "SECRET_POLICY", domainSuffix: "SECRET_SUFFIX", labelRegex: "SECRET_REGEX",
                      transparentConnection: 0, policiesPropertyListXML: "SECRET_XML", policiesJSON: "SECRET_JSON",
                      sourceFingerprint: "SECRET_HASH")
            ])], limitations: ["SECRET_LIMIT"]
        )
        report.database.snapshotSHA256 = "SECRET_SNAPSHOT"
        report.change = .init(baselineID: UUID(), baselineReceiptSHA256: "SECRET_RECEIPT", action: .apply, detail: "SECRET_DETAIL")
        let files = try FeedbackArchive.files(report: report, recoveryPending: true, logs: [
            .init(source: "worker", text: "ERROR SECRET_PAYLOAD\nposix_spawn return=0 pid=99999 SECRET_SERIAL\nunknown SECRET_LINE", truncated: true),
            .init(source: "SECRET_SOURCE", text: "报告已持久化 status=failed SECRET_PATH")
        ])
        XCTAssertEqual(Set(files.keys), ["feedback.json", "events.json", "PRIVACY.txt"])
        let text = files.values.map { String(decoding: $0, as: UTF8.self) }.joined()
        XCTAssertFalse(text.contains("SECRET"))
        XCTAssertFalse(text.contains(seed.sessionID.uuidString))
        XCTAssertFalse(text.contains("99999"))
        XCTAssertTrue(text.contains("iPhone12,1"))
        XCTAssertTrue(text.contains("15.7.1"))
        XCTAssertTrue(text.contains("operation_error"))
        XCTAssertTrue(text.contains("worker_started"))
        XCTAssertTrue(text.contains("other_check"))
    }

    func testInvalidDeviceAndVersionStringsAreNotPassedThrough() throws {
        let seed = DiagnosticEngine.initialReport(sessionID: UUID())
        let report = DiagnosticReport(
            reportFormatVersion: 1, appVersion: "SECRET_VERSION", appBuild: "SECRET_BUILD",
            sessionID: seed.sessionID, startedAt: seed.startedAt, finishedAt: seed.finishedAt,
            status: .failed, identity: seed.identity,
            device: .init(machine: "SECRET_MACHINE", systemVersion: "SECRET_OS", systemBuild: "SECRET_OS_BUILD"),
            database: seed.database, checks: [], hostMatches: [], limitations: []
        )
        let files = try FeedbackArchive.files(report: report, recoveryPending: false)
        XCTAssertFalse(String(decoding: try XCTUnwrap(files["feedback.json"]), as: UTF8.self).contains("SECRET"))
    }

    func testFeedbackWithoutSessionStillRecordsAppAndRecoveryState() throws {
        let files = try FeedbackArchive.files(report: nil, recoveryPending: true)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(files["feedback.json"])) as? [String: Any])
        XCTAssertEqual(object["reportAvailable"] as? Bool, false)
        XCTAssertEqual(object["recoveryPending"] as? Bool, true)
        XCTAssertEqual(object["appVersion"] as? String, DiagnosticAppVersion.current)
    }

    func testDurableCommitProgressOverridesStaleReportWithoutSharingItsReference() throws {
        let report = DiagnosticEngine.initialReport(sessionID: UUID())
        let progress = RuleChangeResult(baselineID: UUID(), baselineReceiptSHA256: "SECRET", action: .apply, commitState: .committed)
        let files = try FeedbackArchive.files(report: report, progress: progress, recoveryPending: true)
        let text = String(decoding: try XCTUnwrap(files["feedback.json"]), as: UTF8.self)
        XCTAssertTrue(text.contains("committed"))
        XCTAssertFalse(text.contains("SECRET"))
        XCTAssertFalse(text.contains(progress.baselineID.uuidString))
    }

    func testOldBuildReportRetainsSourceVersionSeparately() throws {
        let seed = DiagnosticEngine.initialReport(sessionID: UUID())
        let report = DiagnosticReport(
            reportFormatVersion: 1, appVersion: "0.3.0", appBuild: "7", sessionID: seed.sessionID,
            startedAt: seed.startedAt, finishedAt: seed.finishedAt, status: .failed,
            identity: seed.identity, device: seed.device, database: seed.database, checks: [], hostMatches: [], limitations: []
        )
        let files = try FeedbackArchive.files(report: report, recoveryPending: true)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(files["feedback.json"])) as? [String: Any])
        XCTAssertEqual(object["appVersion"] as? String, DiagnosticAppVersion.current)
        XCTAssertEqual(object["appBuild"] as? String, DiagnosticAppVersion.build)
        XCTAssertEqual(object["sourceVersion"] as? String, "0.3.0")
        XCTAssertEqual(object["sourceBuild"] as? String, "7")
    }

    func testZIPHasStandardHeadersAndDeterministicContents() throws {
        let files = ["a.txt": Data("123456789".utf8), "b.json": Data("{}".utf8)]
        let zip = try FeedbackArchive.zip(files: files)
        XCTAssertEqual(FeedbackArchive.crc32(Data("123456789".utf8)), 0xcbf43926)
        XCTAssertEqual(Array(zip.prefix(4)), [0x50, 0x4b, 0x03, 0x04])
        XCTAssertEqual(Array(zip.suffix(22).prefix(4)), [0x50, 0x4b, 0x05, 0x06])
        XCTAssertEqual(zip, try FeedbackArchive.zip(files: files))
        XCTAssertEqual(zip[zip.count - 12], 2)
    }

    func testZIPRejectsPathsInvalidNamesEmptyAndOversizedInputs() {
        for name in ["../secret.txt", "/secret.txt", "a/b.txt", "a.sqlite3", "a\n.txt", "a..txt", "位置.txt"] {
            XCTAssertThrowsError(try FeedbackArchive.zip(files: [name: Data()]), name)
        }
        XCTAssertThrowsError(try FeedbackArchive.zip(files: [:]))
        XCTAssertThrowsError(try FeedbackArchive.zip(files: ["a.txt": Data(repeating: 0, count: 4 * 1024 * 1024 + 1)]))
    }

    func testStageProjectionBoundsEventsAndNeverCopiesUnrecognizedLines() throws {
        let text = Array(repeating: "ERROR SECRET", count: 3000).joined(separator: "\n")
        let files = try FeedbackArchive.files(report: nil, recoveryPending: false, logs: [.init(source: "app", text: text)])
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(files["events.json"])) as? [String: Any])
        XCTAssertEqual((object["entries"] as? [Any])?.count, 2000)
        XCTAssertEqual(object["truncatedSources"] as? [String], ["app"])
        XCTAssertFalse(String(decoding: try XCTUnwrap(files["events.json"]), as: UTF8.self).contains("SECRET"))
    }

    func testFailedBeforeReportStillIncludesTypedAttemptedOperation() throws {
        let files = try FeedbackArchive.files(report: nil, recoveryPending: true, operation: .restore)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(files["feedback.json"])) as? [String: Any])
        XCTAssertEqual(object["operation"] as? String, "restore")
        XCTAssertEqual(object["reportAvailable"] as? Bool, false)
    }

    func testRealReportUsesNumericSystemVersionAndLegacyOSStringIsNormalized() throws {
        let seed = DiagnosticEngine.initialReport(sessionID: UUID())
        XCTAssertNotNil(seed.device.systemVersion.range(of: #"^\d+\.\d+\.\d+$"#, options: .regularExpression))
        let report = DiagnosticReport(
            reportFormatVersion: 1, appVersion: "0.3.0", appBuild: "7", sessionID: seed.sessionID,
            startedAt: seed.startedAt, finishedAt: seed.finishedAt, status: .failed, identity: seed.identity,
            device: .init(machine: "iPhone12,1", systemVersion: "Version 15.7.1 (Build 19H117)", systemBuild: "19H117"),
            database: seed.database, checks: [], hostMatches: [], limitations: []
        )
        let files = try FeedbackArchive.files(report: report, recoveryPending: true)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(files["feedback.json"])) as? [String: Any])
        XCTAssertEqual(object["systemVersion"] as? String, "15.7.1")
    }
}
