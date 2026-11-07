import Darwin
import Foundation
import XCTest
@testable import OSPinCore

final class FileAccessDiagnosticsTests: XCTestCase {
    private var directory: URL!
    private var source: URL { directory.appendingPathComponent("probe.bin") }
    private let contents = Data("not a SQLite database; must not be read by the probe".utf8)

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    }

    override func tearDownWithError() throws { try FileManager.default.removeItem(at: directory) }

    private func inspect(log: @escaping (String) -> Void = { _ in }) -> DiagnosticEnvelope {
        FileAccessDiagnostics.inspect(
            sessionID: UUID(), profile: .root, path: source.path, requireExpectedIdentity: false,
            runtimeEntitlement: entitlementFixture(), log: log
        )
    }

    private func entitlementFixture(pid: Int32 = getpid()) -> RuntimeEntitlementEvidence {
        RuntimeEntitlementEvidence(
            key: RuntimeEntitlement.key, processID: pid, method: RuntimeEntitlement.method,
            state: .boolean, value: true, probeReturnValue: -1, probeErrno: ERANGE,
            readReturnValue: 0, readErrno: 0, blobByteCount: 256, detail: "unit fixture"
        )
    }

    func testOpenConfirmsReadWriteWithoutChangingContentsAttributesOrCreatingSidecars() throws {
        try contents.write(to: source)
        errno = EACCES
        let envelope = inspect()
        let probe = try XCTUnwrap(envelope.report.accessProbes?.first)
        let opened = try XCTUnwrap(probe.open)
        XCTAssertEqual(envelope.report.status, .complete)
        XCTAssertEqual(opened.openErrno, 0)
        XCTAssertEqual(opened.getFlagsErrno, 0)
        XCTAssertEqual(opened.descriptorStatErrno, 0)
        XCTAssertEqual(opened.closeErrno, 0)
        XCTAssertEqual(opened.closeReturnValue, 0)
        XCTAssertTrue(opened.readWriteDescriptorConfirmed)
        XCTAssertEqual(probe.sourceMetadataUnchanged, true)
        XCTAssertEqual(opened.requestedFlags & (O_CREAT | O_TRUNC | O_APPEND), 0)
        XCTAssertNotEqual(opened.requestedFlags & O_NOFOLLOW, 0)
        XCTAssertNil(envelope.snapshot)
        XCTAssertNil(envelope.report.preparation)
        XCTAssertNil(envelope.report.database.schemaVersion)
        XCTAssertEqual(envelope.report.database.writeAccess, "not_tested")
        XCTAssertEqual(try Data(contentsOf: source), contents)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["probe.bin"])
    }

    func testReadOnlyFileReportsExactEACCESWithoutClaimingDiagnosticTransportFailure() throws {
        guard geteuid() != 0 else { throw XCTSkip("DAC denial requires a non-root process") }
        try contents.write(to: source)
        try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: source.path)
        let envelope = inspect()
        let probe = try XCTUnwrap(envelope.report.accessProbes?.first)
        XCTAssertEqual(envelope.report.status, .complete)
        XCTAssertEqual(probe.open?.returnValue, -1)
        XCTAssertEqual(probe.open?.openErrno, EACCES)
        XCTAssertEqual(probe.open?.readWriteDescriptorConfirmed, false)
        XCTAssertNil(probe.open?.closeReturnValue)
        XCTAssertEqual(probe.sourceMetadataUnchanged, true)
        XCTAssertEqual(try Data(contentsOf: source), contents)
        XCTAssertTrue(envelope.report.checks.contains { $0.name == "access_open" && $0.level == .warning })
    }

    func testIdentityMismatchStopsBeforeAnyFilesystemProbe() throws {
        guard geteuid() != 282 else { throw XCTSkip("Requires a process not running as trustd") }
        var logs: [String] = []
        let envelope = FileAccessDiagnostics.inspect(sessionID: UUID(), profile: .trustd, path: source.path, log: { logs.append($0) })
        let probe = try XCTUnwrap(envelope.report.accessProbes?.first)
        XCTAssertEqual(envelope.report.status, .failed)
        XCTAssertFalse(probe.identityVerified)
        XCTAssertTrue(probe.paths.isEmpty)
        XCTAssertNil(probe.open)
        XCTAssertFalse(logs.contains { $0.hasPrefix("metadata") || $0.hasPrefix("open") })
        XCTAssertTrue(FileAccessDiagnostics.validWorkerResult(envelope, profile: .trustd))
        XCTAssertFalse(FileManager.default.fileExists(atPath: source.path))
    }

    func testProtectedPathCannotBypassIdentityGuardThroughLibraryTestOption() throws {
        guard geteuid() != 282 else { throw XCTSkip("Requires a process not running as trustd") }
        let envelope = FileAccessDiagnostics.inspect(sessionID: UUID(), profile: .trustd, requireExpectedIdentity: false, log: { _ in })
        XCTAssertEqual(envelope.report.status, .failed)
        XCTAssertEqual(envelope.report.accessProbes?.first?.paths.count, 0)
    }

    func testMissingSourceCapturesENOENTAndDoesNotCreateIt() throws {
        let envelope = inspect()
        let probe = try XCTUnwrap(envelope.report.accessProbes?.first)
        XCTAssertEqual(envelope.report.status, .partial)
        XCTAssertEqual(probe.paths.last?.statErrno, ENOENT)
        XCTAssertNil(probe.paths.last?.statfsErrno)
        XCTAssertNotNil(probe.paths.last?.statfsSkippedReason)
        XCTAssertNil(probe.open)
        XCTAssertNotNil(probe.skippedReason)
        XCTAssertFalse(FileManager.default.fileExists(atPath: source.path))
    }

    func testSymlinkAndDirectoryAreNeverOpened() throws {
        let target = directory.appendingPathComponent("target")
        try contents.write(to: target)
        try FileManager.default.createSymbolicLink(at: source, withDestinationURL: target)
        XCTAssertNil(inspect().report.accessProbes?.first?.open)
        XCTAssertEqual(try Data(contentsOf: target), contents)
        try FileManager.default.removeItem(at: source)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: false)
        XCTAssertNil(inspect().report.accessProbes?.first?.open)
    }

    func testReplacementBetweenLstatAndOpenIsDetectedAndDescriptorClosed() throws {
        try contents.write(to: source)
        let replacement = directory.appendingPathComponent("replacement")
        let original = directory.appendingPathComponent("original")
        try Data("replacement contents".utf8).write(to: replacement)
        var mutationError: Error?
        var replaced = false
        let envelope = inspect { line in
            guard line.hasPrefix("metadata path=\(self.source.path) "), !replaced else { return }
            replaced = true
            do {
                try FileManager.default.moveItem(at: self.source, to: original)
                try FileManager.default.moveItem(at: replacement, to: self.source)
            } catch { mutationError = error }
        }
        XCTAssertNil(mutationError)
        let probe = try XCTUnwrap(envelope.report.accessProbes?.first)
        XCTAssertEqual(envelope.report.status, .failed)
        XCTAssertEqual(probe.open?.descriptorMatchesSource, false)
        XCTAssertEqual(probe.open?.closeReturnValue, 0)
        XCTAssertEqual(probe.sourceMetadataUnchanged, false)
        XCTAssertEqual(try Data(contentsOf: original), contents)
        XCTAssertEqual(try Data(contentsOf: source), Data("replacement contents".utf8))
    }

    func testSymlinkReplacementAtOpenReturnsRawELOOPWithoutFollowingTarget() throws {
        try contents.write(to: source)
        let target = directory.appendingPathComponent("target")
        try contents.write(to: target)
        var mutationError: Error?
        let envelope = inspect { line in
            guard line.hasPrefix("metadata path=\(self.source.path) ") else { return }
            do {
                try FileManager.default.removeItem(at: self.source)
                try FileManager.default.createSymbolicLink(at: self.source, withDestinationURL: target)
            } catch { mutationError = error }
        }
        XCTAssertNil(mutationError)
        XCTAssertEqual(envelope.report.accessProbes?.first?.open?.openErrno, ELOOP)
        XCTAssertEqual(envelope.report.status, .failed)
        XCTAssertEqual(try Data(contentsOf: target), contents)
    }

    func testMetadataIncludesActualParentsRawFlagsAndMountReadOnlyBit() throws {
        try contents.write(to: source)
        let probe = try XCTUnwrap(inspect().report.accessProbes?.first)
        XCTAssertEqual(probe.paths.map(\.path), [
            directory.deletingLastPathComponent().path, directory.path, source.path
        ])
        for path in probe.paths {
            XCTAssertEqual(path.statErrno, 0)
            XCTAssertEqual(path.statfsErrno, 0)
            let mount = try XCTUnwrap(path.mount)
            XCTAssertFalse(mount.filesystem.isEmpty)
            XCTAssertTrue(mount.mountPoint.hasPrefix("/"))
            XCTAssertEqual(mount.readOnly, mount.flags & UInt32(MNT_RDONLY) != 0)
        }
        let attributes = try XCTUnwrap(probe.paths.last?.attributes)
        XCTAssertEqual(attributes.ownerID, getuid())
        XCTAssertEqual(attributes.groupID, getgid())
        XCTAssertEqual(attributes.size, Int64(contents.count))
        var flags = stat()
        flags.st_flags = UInt32(UF_IMMUTABLE | SF_APPEND | SF_RESTRICTED)
        XCTAssertEqual(FileNodeAttributes(flags).flagNames, ["UF_IMMUTABLE", "SF_APPEND", "SF_RESTRICTED"])
    }

    func testStrictWorkerProtocolOnlyAcceptsFixedProfilesAndUUID() {
        let id = UUID()
        for profile in FileAccessProfile.allCases {
            XCTAssertEqual(DiagnosticWorkerRequest.parse(["--permissions", id.uuidString, profile.rawValue]), .permissions(id, profile))
        }
        for args in [
            ["--permissions", "invalid", "root"], ["--permissions", id.uuidString],
            ["--permissions", id.uuidString, "0"], ["--permissions", id.uuidString, "282"],
            ["--permissions", id.uuidString, "mobile"], ["--permissions", id.uuidString, "root", "/tmp/file"]
        ] { XCTAssertNil(DiagnosticWorkerRequest.parse(args)) }
    }

    func testIncompleteOrDuplicateProfilesCannotBecomeCompleteComparison() throws {
        let envelope = FileAccessDiagnostics.inspect(sessionID: UUID(), profile: .trustd, path: source.path, log: { _ in })
        let probe = try XCTUnwrap(envelope.report.accessProbes?.first)
        XCTAssertEqual(FileAccessDiagnostics.comparisonStatus(probes: [probe], failures: []), .partial)
        XCTAssertEqual(FileAccessDiagnostics.comparisonStatus(probes: [probe, probe], failures: []), .partial)
        XCTAssertEqual(FileAccessDiagnostics.comparisonStatus(probes: [probe], failures: [.init(profile: .root, detail: "spawn failed")]), .partial)
    }

    func testWorkerResultRejectsWrongProfileIdentityAndUnexpectedSnapshot() throws {
        let envelope = FileAccessDiagnostics.inspect(sessionID: UUID(), profile: .trustd, path: source.path, log: { _ in })
        XCTAssertTrue(FileAccessDiagnostics.validWorkerResult(envelope, profile: .trustd))
        XCTAssertFalse(FileAccessDiagnostics.validWorkerResult(envelope, profile: .root))
        XCTAssertFalse(FileAccessDiagnostics.validWorkerResult(.init(report: envelope.report, snapshot: Data()), profile: .trustd))
        var report = envelope.report
        report.status = .complete
        XCTAssertFalse(FileAccessDiagnostics.validWorkerResult(.init(report: report, snapshot: nil), profile: .trustd))
    }

    func testCompleteWorkerProtocolRequiresConfirmedReadWriteMode() throws {
        try contents.write(to: source)
        let captured = inspect().report
        let result = try XCTUnwrap(captured.accessProbes?.first)
        let identity = ProcessIdentity(uid: 0, effectiveUID: 0, gid: 0, effectiveGID: 0, pid: 123)
        let fixture = FileAccessProbe(
            profile: .root, identity: identity, status: .complete, identityVerified: true,
            paths: result.paths, open: result.open, afterStatErrno: result.afterStatErrno,
            afterAttributes: result.afterAttributes, sourceMetadataUnchanged: result.sourceMetadataUnchanged,
            runtimeEntitlement: entitlementFixture(pid: identity.pid)
        )
        var report = DiagnosticReport(
            reportFormatVersion: 1, appVersion: captured.appVersion, appBuild: captured.appBuild,
            sessionID: captured.sessionID, startedAt: captured.startedAt, finishedAt: captured.finishedAt,
            status: .complete, identity: identity, device: captured.device, database: captured.database,
            checks: [], hostMatches: [], operation: .permissions, accessProbes: [fixture], limitations: []
        )
        XCTAssertTrue(FileAccessDiagnostics.validWorkerResult(.init(report: report, snapshot: nil), profile: .root))
        report.accessProbes?[0].open?.getFlagsReturnValue = O_RDONLY
        XCTAssertFalse(FileAccessDiagnostics.validWorkerResult(.init(report: report, snapshot: nil), profile: .root))
        report.accessProbes?[0].open?.getFlagsReturnValue = O_RDWR
        report.accessProbes?[0].runtimeEntitlement = nil
        XCTAssertFalse(FileAccessDiagnostics.validWorkerResult(.init(report: report, snapshot: nil), profile: .root))
        let legacy = try DiagnosticEncoding.decoder().decode(
            DiagnosticReport.self, from: DiagnosticEncoding.encoder().encode(report)
        )
        XCTAssertNil(legacy.accessProbes?.first?.runtimeEntitlement)
        XCTAssertTrue(DiagnosticSummary.text(legacy).contains("旧报告未采集"))
    }

    func testPermissionReportRoundTripsAndSummaryDoesNotImplySQLiteRan() throws {
        try contents.write(to: source)
        let report = inspect().report
        let decoded = try DiagnosticEncoding.decoder().decode(DiagnosticReport.self, from: DiagnosticEncoding.encoder().encode(report))
        XCTAssertEqual(decoded.accessProbes?.first?.open?.openErrno, 0)
        let summary = DiagnosticSummary.text(decoded)
        XCTAssertTrue(summary.contains("不是写权限结论"))
        XCTAssertTrue(summary.contains("未调用 SQLite"))
        XCTAssertTrue(summary.contains("open flags="))
        XCTAssertFalse(summary.contains("Schema:"))
        XCTAssertTrue(summary.contains(RuntimeEntitlement.key))
    }

    func testUnavailableEntitlementQueryStillProbesOwnedFixtureButCannotClaimComplete() throws {
        try contents.write(to: source)
        let evidence = RuntimeEntitlement.capture { _ in (-1, EPERM) }
        let envelope = FileAccessDiagnostics.inspect(
            sessionID: UUID(), profile: .root, path: source.path, requireExpectedIdentity: false,
            runtimeEntitlement: evidence, log: { _ in }
        )
        XCTAssertEqual(envelope.report.status, .partial)
        XCTAssertEqual(envelope.report.accessProbes?.first?.open?.readWriteDescriptorConfirmed, true)
        XCTAssertNil(envelope.report.accessProbes?.first?.runtimeEntitlement?.value)
        XCTAssertEqual(try Data(contentsOf: source), contents)
    }
}
