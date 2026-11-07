import Darwin
import Foundation

public enum FileAccessProfile: String, Codable, CaseIterable {
    case root, trustd

    public var id: UInt32 { self == .root ? 0 : 282 }

    public func matches(_ identity: ProcessIdentity) -> Bool {
        identity.uid == id && identity.effectiveUID == id && identity.gid == id && identity.effectiveGID == id
    }
}

public struct FileNodeAttributes: Codable, Equatable {
    public let deviceID: Int32
    public let fileID: UInt64
    public let mode: UInt16
    public let ownerID: UInt32
    public let groupID: UInt32
    public let size: Int64
    public let flags: UInt32
    public let modifiedSeconds: Int64
    public let modifiedNanoseconds: Int64
    public let changedSeconds: Int64
    public let changedNanoseconds: Int64

    init(_ value: stat) {
        deviceID = value.st_dev
        fileID = value.st_ino
        mode = value.st_mode
        ownerID = value.st_uid
        groupID = value.st_gid
        size = value.st_size
        flags = value.st_flags
        modifiedSeconds = Int64(value.st_mtimespec.tv_sec)
        modifiedNanoseconds = Int64(value.st_mtimespec.tv_nsec)
        changedSeconds = Int64(value.st_ctimespec.tv_sec)
        changedNanoseconds = Int64(value.st_ctimespec.tv_nsec)
    }

    public var isRegularFile: Bool { mode & UInt16(S_IFMT) == UInt16(S_IFREG) }
    public var isDirectory: Bool { mode & UInt16(S_IFMT) == UInt16(S_IFDIR) }
    public var flagNames: [String] {
        let known: [(UInt32, String)] = [
            (UInt32(UF_IMMUTABLE), "UF_IMMUTABLE"), (UInt32(SF_IMMUTABLE), "SF_IMMUTABLE"),
            (UInt32(UF_APPEND), "UF_APPEND"), (UInt32(SF_APPEND), "SF_APPEND"),
            (UInt32(UF_HIDDEN), "UF_HIDDEN"), (UInt32(SF_RESTRICTED), "SF_RESTRICTED")
        ]
        return known.filter { flags & $0.0 != 0 }.map(\.1)
    }
}

public struct FileMountInformation: Codable {
    public let flags: UInt32
    public let readOnly: Bool
    public let filesystem: String
    public let mountPoint: String
}

public struct FilePathEvidence: Codable {
    public let path: String
    public let statErrno: Int32
    public let attributes: FileNodeAttributes?
    public let statfsErrno: Int32?
    public let statfsSkippedReason: String?
    public let mount: FileMountInformation?
}

public struct FileOpenEvidence: Codable {
    public let requestedFlags: Int32
    public let returnValue: Int32
    public let openErrno: Int32
    public var getFlagsReturnValue: Int32?
    public var getFlagsErrno: Int32?
    public var descriptorStatErrno: Int32?
    public var descriptorAttributes: FileNodeAttributes?
    public var descriptorMatchesSource: Bool?
    public var closeReturnValue: Int32?
    public var closeErrno: Int32?

    public var readWriteDescriptorConfirmed: Bool {
        returnValue >= 0 && getFlagsReturnValue.map { $0 & O_ACCMODE == O_RDWR } == true
            && descriptorMatchesSource == true
    }
}

public struct FileAccessProbe: Codable {
    public let profile: FileAccessProfile
    public let identity: ProcessIdentity
    public var status: DiagnosticStatus
    public let identityVerified: Bool
    public var paths: [FilePathEvidence]
    public var open: FileOpenEvidence?
    public var skippedReason: String?
    public var afterStatErrno: Int32?
    public var afterAttributes: FileNodeAttributes?
    public var sourceMetadataUnchanged: Bool?
    public var runtimeEntitlement: RuntimeEntitlementEvidence?
}

public struct FileAccessFailure: Codable {
    public let profile: FileAccessProfile
    public let detail: String

    public init(profile: FileAccessProfile, detail: String) {
        self.profile = profile
        self.detail = detail
    }
}

public enum FileAccessDiagnostics {
    public static let openFlags = O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK

    public static func validWorkerResult(_ envelope: DiagnosticEnvelope, profile: FileAccessProfile) -> Bool {
        let report = envelope.report
        guard report.operation == .permissions, envelope.snapshot == nil, report.preparation == nil,
              report.hostMatches.isEmpty, report.database.snapshotSHA256 == nil,
              report.database.writeAccess == "not_tested",
              report.accessFailures == nil, report.accessProbes?.count == 1,
              let probe = report.accessProbes?.first, probe.profile == profile,
              probe.identity == report.identity, probe.status == report.status,
              probe.identityVerified == profile.matches(report.identity),
              let entitlement = probe.runtimeEntitlement, entitlement.isConsistent,
              entitlement.processID == report.identity.pid else { return false }
        if !probe.identityVerified {
            return probe.status == .failed && probe.paths.isEmpty && probe.open == nil
                && probe.afterAttributes == nil && probe.sourceMetadataUnchanged == nil
        }
        let source = URL(fileURLWithPath: report.database.sourcePath)
        let parent = source.deletingLastPathComponent()
        guard probe.paths.map(\.path) == [parent.deletingLastPathComponent().path, parent.path, source.path] else { return false }
        if let opened = probe.open, opened.requestedFlags != openFlags { return false }
        if probe.status == .complete {
            guard entitlement.state != .unavailable,
                  probe.paths.allSatisfy({ $0.statErrno == 0 && $0.statfsErrno == 0 && $0.attributes != nil && $0.mount != nil }),
                  probe.sourceMetadataUnchanged == true, probe.afterStatErrno == 0,
                  let opened = probe.open else { return false }
            if opened.returnValue < 0 { return opened.openErrno > 0 }
            return opened.openErrno == 0 && opened.readWriteDescriptorConfirmed
                && opened.getFlagsErrno == 0 && opened.descriptorStatErrno == 0 && opened.closeErrno == 0
                && opened.closeReturnValue == 0
        }
        return true
    }

    public static func comparisonStatus(probes: [FileAccessProbe], failures: [FileAccessFailure]) -> DiagnosticStatus {
        let covered = probes.map(\.profile) + failures.map(\.profile)
        guard covered.count == 2, Set(covered) == Set(FileAccessProfile.allCases) else { return .partial }
        if probes.count == 2 && probes.allSatisfy({ $0.status == .failed }) { return .failed }
        return failures.isEmpty && probes.allSatisfy({ $0.status == .complete }) ? .complete : .partial
    }

    public static func inspect(
        sessionID: UUID, profile: FileAccessProfile,
        path: String = DiagnosticEngine.protectedDatabasePath,
        requireExpectedIdentity: Bool = true,
        runtimeEntitlement: RuntimeEntitlementEvidence = RuntimeEntitlement.captureSelf(),
        log: (String) -> Void
    ) -> DiagnosticEnvelope {
        var report = DiagnosticEngine.initialReport(sessionID: sessionID, path: path, operation: .permissions)
        var probe = FileAccessProbe(
            profile: profile, identity: report.identity, status: .failed,
            identityVerified: profile.matches(report.identity), paths: [], runtimeEntitlement: runtimeEntitlement
        )
        func finish() -> DiagnosticEnvelope {
            report.status = probe.status
            report.finishedAt = Date()
            report.accessProbes = [probe]
            log("权限采集结束 profile=\(profile.rawValue) status=\(probe.status.rawValue)；未读写源内容")
            return DiagnosticEnvelope(report: report, snapshot: nil)
        }
        log("权限采集 profile=\(profile.rawValue) requested_uid/gid=\(profile.id) actual_uid/euid=\(report.identity.uid)/\(report.identity.effectiveUID) gid/egid=\(report.identity.gid)/\(report.identity.effectiveGID)")
        log("runtime_entitlement key=\(runtimeEntitlement.key) method=\(runtimeEntitlement.method) pid=\(runtimeEntitlement.processID) state=\(runtimeEntitlement.state.rawValue) value=\(runtimeEntitlement.value.map(String.init) ?? "unknown") probe_return=\(runtimeEntitlement.probeReturnValue.map(String.init) ?? "not_called") probe_errno=\(runtimeEntitlement.probeErrno.map(String.init) ?? "not_called") read_return=\(runtimeEntitlement.readReturnValue.map(String.init) ?? "not_called") read_errno=\(runtimeEntitlement.readErrno.map(String.init) ?? "not_called")")
        report.checks.append(DiagnosticCheck(
            name: "runtime_storage_entitlement",
            level: runtimeEntitlement.state == .boolean && runtimeEntitlement.value == true ? .pass : .warning,
            detail: runtimeEntitlement.detail
        ))
        report.checks.append(DiagnosticCheck(
            name: "access_identity", level: probe.identityVerified ? .pass : .fail,
            detail: "profile=\(profile.rawValue) expected UID/GID=\(profile.id) actual=\(report.identity.uid)/\(report.identity.effectiveUID)/\(report.identity.gid)/\(report.identity.effectiveGID)"
        ))
        if !probe.identityVerified && (requireExpectedIdentity || path == DiagnosticEngine.protectedDatabasePath) {
            let reason = "身份不匹配；未访问受保护路径"
            probe.skippedReason = reason
            log("ERROR \(reason)")
            return finish()
        }
        let source = URL(fileURLWithPath: path)
        let parent = source.deletingLastPathComponent()
        let paths = [parent.deletingLastPathComponent().path, parent.path, path]
        probe.paths = paths.map { metadata($0, log: log) }
        guard let before = probe.paths.last?.attributes, before.isRegularFile,
              probe.paths.dropLast().allSatisfy({ $0.attributes?.isDirectory == true }) else {
            probe.status = .partial
            let reason = "无法确认源为普通文件且两个父路径为目录；不尝试打开"
            probe.skippedReason = reason
            report.checks.append(DiagnosticCheck(name: "access_path_guard", level: .warning, detail: reason))
            log("WARNING \(reason)")
            return finish()
        }
        probe.status = runtimeEntitlement.state != .unavailable &&
            probe.paths.allSatisfy { $0.statErrno == 0 && $0.statfsErrno == 0 } ? .complete : .partial
        let fd = Darwin.open(path, openFlags)
        let openError = fd < 0 ? errno : 0
        var opened = FileOpenEvidence(requestedFlags: openFlags, returnValue: fd, openErrno: openError)
        log("open O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK return=\(fd) errno=\(openError) \(errorText(openError))")
        if fd >= 0 {
            let flags = fcntl(fd, F_GETFL)
            let flagsError = flags < 0 ? errno : 0
            opened.getFlagsReturnValue = flags
            opened.getFlagsErrno = flagsError
            var value = stat()
            let statResult = fstat(fd, &value)
            opened.descriptorStatErrno = statResult < 0 ? errno : 0
            if statResult == 0 {
                opened.descriptorAttributes = FileNodeAttributes(value)
                opened.descriptorMatchesSource = opened.descriptorAttributes == before
            }
            let closed = close(fd)
            opened.closeErrno = closed < 0 ? errno : 0
            opened.closeReturnValue = closed
            log("F_GETFL return=\(flags) errno=\(flagsError) fstat_errno=\(opened.descriptorStatErrno ?? -1) matches_source=\(opened.descriptorMatchesSource.map(String.init) ?? "unknown") close=\(closed) close_errno=\(opened.closeErrno ?? -1)")
            if !opened.readWriteDescriptorConfirmed || closed != 0 {
                probe.status = .failed
                report.checks.append(DiagnosticCheck(name: "access_descriptor", level: .fail, detail: "文件描述符身份、读写模式或关闭验证失败；见原始返回值"))
            }
        }
        probe.open = opened
        var after = stat()
        let afterResult = lstat(path, &after)
        probe.afterStatErrno = afterResult < 0 ? errno : 0
        if afterResult == 0 {
            probe.afterAttributes = FileNodeAttributes(after)
            probe.sourceMetadataUnchanged = probe.afterAttributes == before
        }
        if probe.sourceMetadataUnchanged != true {
            probe.status = .failed
            report.checks.append(DiagnosticCheck(name: "access_source_changed", level: .fail, detail: "源元数据变化或无法复查；不推断内容一致"))
        }
        log("after_lstat errno=\(probe.afterStatErrno ?? -1) metadata_unchanged=\(probe.sourceMetadataUnchanged.map(String.init) ?? "unknown")")
        report.checks.append(DiagnosticCheck(
            name: "access_open", level: opened.readWriteDescriptorConfirmed ? .pass : .warning,
            detail: "profile=\(profile.rawValue) O_RDWR return=\(fd) errno=\(openError) \(errorText(openError))；只打开并关闭，不证明真实写入或 COMMIT"
        ))
        return finish()
    }

    private static func metadata(_ path: String, log: (String) -> Void) -> FilePathEvidence {
        var value = stat()
        let result = lstat(path, &value)
        let statError = result < 0 ? errno : 0
        // Do not follow a symlink discovered by lstat, even for the mount query.
        var filesystem = statfs()
        let canQueryMount = result == 0 && (value.st_mode & S_IFMT == S_IFREG || value.st_mode & S_IFMT == S_IFDIR)
        let mountResult = canQueryMount ? statfs(path, &filesystem) : -1
        let mountError: Int32? = canQueryMount ? (mountResult < 0 ? errno : 0) : nil
        let mount: FileMountInformation? = mountResult == 0 ? FileMountInformation(
            flags: filesystem.f_flags, readOnly: filesystem.f_flags & UInt32(MNT_RDONLY) != 0,
            filesystem: tupleString(filesystem.f_fstypename), mountPoint: tupleString(filesystem.f_mntonname)
        ) : nil
        let attributes = result == 0 ? FileNodeAttributes(value) : nil
        log("metadata path=\(path) lstat_errno=\(statError) statfs_errno=\(mountError.map(String.init) ?? "not_attempted") mode=\(attributes.map { String(format: "%06o", $0.mode) } ?? "unknown") uid/gid=\(attributes.map { "\($0.ownerID)/\($0.groupID)" } ?? "unknown") flags=\(attributes.map { String(format: "0x%08x", $0.flags) } ?? "unknown") mount_readonly=\(mount.map { String($0.readOnly) } ?? "unknown")")
        return FilePathEvidence(
            path: path, statErrno: statError, attributes: attributes, statfsErrno: mountError,
            statfsSkippedReason: canQueryMount ? nil : "lstat 失败或不是普通文件/目录；未调用 statfs", mount: mount
        )
    }

    private static func tupleString<T>(_ value: T) -> String {
        withUnsafeBytes(of: value) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }

    public static func errorText(_ code: Int32) -> String {
        code == 0 ? "success" : String(cString: strerror(code))
    }
}
