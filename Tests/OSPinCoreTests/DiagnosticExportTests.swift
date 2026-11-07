import CryptoKit
import Foundation
import XCTest
@testable import OSPinCore

final class DiagnosticExportTests: XCTestCase {
    private var directory: URL!
    private var source: URL!
    private var exports: URL!
    private var sessionID: UUID!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        sessionID = UUID()
        source = directory.appendingPathComponent("LegacyDocuments/Sessions/\(sessionID.uuidString)", isDirectory: true)
        exports = directory.appendingPathComponent("Media/Exports", isDirectory: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    func testExportCopiesLegacyFilesWithoutChangingSourceAndVerifiesHashes() throws {
        let files = [
            "summary.txt": "legacy report",
            "report.json": #"{"appVersion":"0.1.0","status":"failed"}"#,
            "app.log": "legacy application log",
            "worker.log": "legacy worker log",
            "pinningrules.snapshot.sqlite3": "snapshot test bytes"
        ]
        for (name, text) in files {
            try Data(text.utf8).write(to: source.appendingPathComponent(name))
        }
        let result = try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports)
        XCTAssertEqual(result.receipt.appVersion, DiagnosticAppVersion.current)
        XCTAssertEqual(result.receipt.sessionID, sessionID)
        XCTAssertTrue(result.receipt.missingSessionFiles.isEmpty)
        XCTAssertEqual(result.receipt.files.count, 5)
        for file in result.receipt.files {
            let original = try Data(contentsOf: source.appendingPathComponent(file.name))
            let copied = try Data(contentsOf: result.directory.appendingPathComponent(file.name))
            XCTAssertEqual(original, copied)
            XCTAssertEqual(String(data: original, encoding: .utf8), files[file.name])
            XCTAssertEqual(file.byteCount, UInt64(copied.count))
            XCTAssertEqual(file.sha256, SHA256.hash(data: copied).map { String(format: "%02x", $0) }.joined())
        }
        let receipt = try DiagnosticEncoding.decoder().decode(
            DiagnosticExportReceipt.self, from: Data(contentsOf: result.directory.appendingPathComponent("receipt.json"))
        )
        XCTAssertEqual(receipt.exportID, result.receipt.exportID)
    }

    func testFailedDiagnosticCanExportOnlyItsAvailableLogs() throws {
        try Data("ERROR persona failed".utf8).write(to: source.appendingPathComponent("app.log"))
        let result = try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports)
        XCTAssertEqual(result.receipt.files.map(\.name), ["app.log"])
        XCTAssertTrue(result.receipt.missingSessionFiles.contains("report.json"))
        XCTAssertTrue(result.receipt.missingSessionFiles.contains("pinningrules.snapshot.sqlite3"))
    }

    func testEmptySessionFailsWithoutSuccessReceipt() {
        XCTAssertThrowsError(try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports))
        XCTAssertFalse(FileManager.default.fileExists(atPath: exports.path))
    }

    func testSymbolicLinkCannotExportAnUnrelatedFile() throws {
        let unrelated = directory.appendingPathComponent("unrelated.txt")
        try Data("unrelated".utf8).write(to: unrelated)
        try FileManager.default.createSymbolicLink(
            at: source.appendingPathComponent("app.log"), withDestinationURL: unrelated
        )
        XCTAssertThrowsError(try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports)) {
            XCTAssertTrue($0.localizedDescription.contains("非普通文件"))
        }
        let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: exports, includingPropertiesForKeys: nil))
        XCTAssertFalse(enumerator.allObjects.compactMap { $0 as? URL }.contains { $0.lastPathComponent == "receipt.json" })
    }

    func testRepeatedExportsReplaceLatestAndRemoveStaleSnapshot() throws {
        try Data("session".utf8).write(to: source.appendingPathComponent("app.log"))
        try Data("snapshot".utf8).write(to: source.appendingPathComponent("pinningrules.snapshot.sqlite3"))
        let applicationLog = directory.appendingPathComponent("application.log")
        try Data("startup".utf8).write(to: applicationLog)
        let first = try DiagnosticExporter.export(
            sessionID: sessionID, sourceDirectory: source, exportRoot: exports, applicationLog: applicationLog
        )
        try FileManager.default.removeItem(at: source.appendingPathComponent("pinningrules.snapshot.sqlite3"))
        try Data("new session".utf8).write(to: source.appendingPathComponent("app.log"))
        let second = try DiagnosticExporter.export(
            sessionID: sessionID, sourceDirectory: source, exportRoot: exports, applicationLog: applicationLog
        )
        XCTAssertEqual(first.directory, second.directory)
        XCTAssertNotEqual(first.receipt.exportID, second.receipt.exportID)
        XCTAssertEqual(second.receipt.files.map(\.name), ["app.log", "application.log"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: second.directory.appendingPathComponent("pinningrules.snapshot.sqlite3").path))
        XCTAssertEqual(try String(contentsOf: second.directory.appendingPathComponent("app.log"), encoding: .utf8), "new session")
        XCTAssertEqual(second.receipt.appBuild, DiagnosticAppVersion.build)
    }

    func testFailedCopyKeepsPreviousLatest() throws {
        try Data("valid log".utf8).write(to: source.appendingPathComponent("app.log"))
        let first = try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports)
        let receipt = try Data(contentsOf: first.directory.appendingPathComponent("receipt.json"))
        try FileManager.default.removeItem(at: source.appendingPathComponent("app.log"))
        try FileManager.default.createSymbolicLink(at: source.appendingPathComponent("app.log"), withDestinationURL: first.directory.appendingPathComponent("app.log"))
        XCTAssertThrowsError(try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports))
        XCTAssertEqual(try Data(contentsOf: first.directory.appendingPathComponent("receipt.json")), receipt)
        XCTAssertEqual(try String(contentsOf: first.directory.appendingPathComponent("app.log"), encoding: .utf8), "valid log")
    }

    func testLegacyExportCleanupDoesNotDeleteSourceSessionsOrUnrelatedFiles() throws {
        try Data("original".utf8).write(to: source.appendingPathComponent("app.log"))
        let first = try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports)
        let oldParent = exports.appendingPathComponent(sessionID.uuidString)
        try FileManager.default.createDirectory(at: oldParent, withIntermediateDirectories: true)
        try FileManager.default.moveItem(at: first.directory, to: oldParent.appendingPathComponent(first.receipt.exportID.uuidString))
        let unrelated = exports.appendingPathComponent("keep.txt")
        try Data("keep".utf8).write(to: unrelated)
        _ = try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports)
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldParent.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: unrelated.path))
        XCTAssertEqual(try String(contentsOf: source.appendingPathComponent("app.log"), encoding: .utf8), "original")
    }

    func testWorkerEnvironmentPreservesRuntimeAndRejectsInjectionForDevice() {
        let current = [
            "HOME": "/var/mobile", "TMPDIR": "/tmp/runtime", "CFFIXED_USER_HOME": "/var/mobile",
            "PATH": "/usr/bin", "VALUE": "with=equals",
            "DYLD_INSERT_LIBRARIES": "/test/injection.dylib", "DYLD_LIBRARY_PATH": "/test/libraries",
            "DYLD_VERSIONED_LIBRARY_PATH": "/test/versioned", "DYLD_ROOT_PATH": "/test/root"
        ]
        let environment = WorkerEnvironment.make(current: current, simulator: false)
        XCTAssertTrue(environment.contains("HOME=/var/mobile"))
        XCTAssertTrue(environment.contains("TMPDIR=/tmp/runtime"))
        XCTAssertTrue(environment.contains("CFFIXED_USER_HOME=/var/mobile"))
        XCTAssertTrue(environment.contains("VALUE=with=equals"))
        XCTAssertFalse(environment.contains { $0.hasPrefix("DYLD_") })
    }

    func testLegacyCleanupPreservesUnknownFiles() throws {
        try Data("original".utf8).write(to: source.appendingPathComponent("app.log"))
        let first = try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports)
        let oldParent = exports.appendingPathComponent(sessionID.uuidString)
        try FileManager.default.createDirectory(at: oldParent, withIntermediateDirectories: true)
        let oldExport = oldParent.appendingPathComponent(first.receipt.exportID.uuidString)
        try FileManager.default.moveItem(at: first.directory, to: oldExport)
        let unknown = oldExport.appendingPathComponent("keep.txt")
        try Data("keep".utf8).write(to: unknown)
        XCTAssertThrowsError(try DiagnosticExporter.export(sessionID: sessionID, sourceDirectory: source, exportRoot: exports))
        XCTAssertTrue(FileManager.default.fileExists(atPath: unknown.path))
    }

    func testOldReportWithoutAppBuildStillDecodes() throws {
        let envelope = DiagnosticEngine.inspect(path: directory.appendingPathComponent("missing.sqlite").path, sessionID: sessionID, requireRoot: false) { _ in }
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: DiagnosticEncoding.encoder().encode(envelope.report)) as? [String: Any])
        object.removeValue(forKey: "appBuild")
        let report = try DiagnosticEncoding.decoder().decode(
            DiagnosticReport.self, from: JSONSerialization.data(withJSONObject: object)
        )
        XCTAssertNil(report.appBuild)
        XCTAssertTrue(DiagnosticSummary.text(report).contains("应用 Build: 旧版未记录"))
    }

    func testSimulatorEnvironmentRemainsIntact() {
        let current = ["DYLD_ROOT_PATH": "/simulator/runtime", "SIMULATOR_UDID": "test", "HOME": "/simulator/home"]
        XCTAssertEqual(WorkerEnvironment.make(current: current, simulator: true), current.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" })
    }

    func testManifestAndReportVersionsAgree() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("Resources/Info.plist"))
        let info = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any])
        XCTAssertEqual(info["CFBundleShortVersionString"] as? String, DiagnosticAppVersion.current)
        XCTAssertEqual(info["CFBundleVersion"] as? String, DiagnosticAppVersion.build)
    }
}
