import Darwin
import Foundation
import SQLite3

public enum RuleCommitState: String, Codable {
    case notAttempted, committing, committed, rolledBack, unknown
}

public struct RuleChangeResult: Codable {
    public let baselineID: UUID
    public let baselineReceiptSHA256: String
    public let action: DiagnosticOperation
    public var commitState: RuleCommitState = .notAttempted
    public var verified = false
    public var alreadyRestored = false
    public var targetFingerprint: String?
    public var beforeRuleCount: Int?
    public var afterRuleCount: Int?
    public var detail = "尚未修改；不自动重载服务或保证定位恢复"
}

public struct RuleRecoveryReference: Codable {
    public let baselineID: UUID
    public let receiptSHA256: String

    public init(baselineID: UUID, receiptSHA256: String) {
        self.baselineID = baselineID
        self.receiptSHA256 = receiptSHA256
    }
}

private struct RuleDatabaseState: Equatable {
    let schema: [String]
    let admin: [String]
    var rules: [String]

    init(_ database: PreparationDatabase) throws {
        try database.validateLayout()
        schema = try database.rows("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
        admin = try database.rows("SELECT rowid,* FROM admin")
        rules = try database.rows("SELECT rowid,* FROM rules")
    }
}

public enum ControlledRuleChange {
    public static let progressFileName = "change-progress.json"
    public static let referenceFileName = "recovery-reference.json"

    public static func persist(_ result: RuleChangeResult, at url: URL) throws {
        try DiagnosticEncoding.encoder(pretty: true).encode(result).write(to: url, options: .atomic)
        let handle = try FileHandle(forWritingTo: url)
        do {
            try handle.synchronize()
            try handle.close()
        } catch {
            try handle.close()
            throw error
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
    }

    public static func run(
        action: DiagnosticOperation, sessionID: UUID, reference: RuleRecoveryReference,
        baselineDirectory: URL, path: String = DiagnosticEngine.protectedDatabasePath,
        requireRoot: Bool = true, persist: (RuleChangeResult) throws -> Void, log: (String) -> Void
    ) -> DiagnosticEnvelope {
        var report = DiagnosticEngine.initialReport(sessionID: sessionID, path: path, operation: action)
        var result = RuleChangeResult(baselineID: reference.baselineID, baselineReceiptSHA256: reference.receiptSHA256, action: action)
        var snapshot: Data?
        do {
            guard action == .apply || action == .restore else { throw PinningPreparation.failure("非法变更动作") }
            guard !requireRoot || [report.identity.uid, report.identity.effectiveUID, report.identity.gid, report.identity.effectiveGID].allSatisfy({ $0 == 0 }) else {
                throw PinningPreparation.failure("root 验证失败；未读取或修改受保护数据库")
            }
            try persist(result)
            let receiptURL = baselineDirectory.appendingPathComponent("baseline-receipt.json")
            try RecoveryBaselineStore.verify(directory: baselineDirectory, sessionID: reference.baselineID, requireCurrentBuild: false)
            guard PinningPreparation.sha256(try Data(contentsOf: receiptURL)) == reference.receiptSHA256 else {
                throw PinningPreparation.failure("恢复基线清单摘要已变化")
            }
            let receipt = try DiagnosticEncoding.decoder().decode(RecoveryBaselineReceipt.self, from: Data(contentsOf: receiptURL))
            let baselineReport = try DiagnosticEncoding.decoder().decode(
                DiagnosticReport.self, from: Data(contentsOf: baselineDirectory.appendingPathComponent("baseline-report.json"))
            )
            let target = try PinningPreparation.targetRule(in: baselineReport)
            let baseline = try PreparationDatabase(path: baselineDirectory.appendingPathComponent("baseline.sqlite3").path, writable: false)
            let original = try RuleDatabaseState(baseline)
            try baseline.quickCheck()
            let rows = try baseline.targetRows()
            guard rows.count == 1, let row = rows.first, try row.fingerprint() == target.sourceFingerprint else {
                throw PinningPreparation.failure("基线目标行不唯一或原始 BLOB 指纹不符")
            }
            result.targetFingerprint = try row.fingerprint()
            let rowID = try baseline.targetRowID()
            var applied = original
            applied.rules = try baseline.rows("SELECT rowid,* FROM rules WHERE NOT (policyName='AppleIssued' AND domainSuffix='apple.com' AND labelRegex='^gs-loc$|^gs-loc-cn$')")
            guard original.rules.count == applied.rules.count + 1 else { throw PinningPreparation.failure("候选差异不是单行") }
            let sourceIdentity = try checkPath(path, expected: receipt.database, allowDeviceChange: action == .restore)
            if sourceIdentity.deviceID != receipt.database.deviceID {
                log("恢复预检：挂载设备号已变化；保留原始 inode/属主/权限门槛，锁内仍须完整逻辑匹配，并固定本次文件身份")
            }
            let initial = DiagnosticEngine.inspect(path: path, sessionID: sessionID, requireRoot: requireRoot, log: log)
            guard initial.snapshot != nil else { throw PinningPreparation.failure("变更前只读快照失败") }
            report.database = initial.report.database
            report.hostMatches = initial.report.hostMatches
            snapshot = initial.snapshot
            let database = try PreparationDatabase(path: path, writable: true)
            guard sqlite3_db_readonly(database.handle, "main") == 0 else { throw PinningPreparation.failure("源连接是只读") }
            try database.execute("PRAGMA synchronous=FULL")
            let authorizer = sqlite3_set_authorizer(database.handle, { _, action, table, _, _, trigger in
                if trigger != nil { return SQLITE_DENY }
                switch action {
                case SQLITE_SELECT, SQLITE_READ, SQLITE_TRANSACTION, SQLITE_FUNCTION, SQLITE_PRAGMA: return SQLITE_OK
                case SQLITE_DELETE, SQLITE_INSERT:
                    return table.map { String(cString: $0) == "rules" } == true ? SQLITE_OK : SQLITE_DENY
                default: return SQLITE_DENY
                }
            }, nil)
            guard authorizer == SQLITE_OK else { throw PinningPreparation.failure("设置受限 authorizer 失败") }
            try database.execute("BEGIN IMMEDIATE")
            do {
                try checkIdentity(path, expected: sourceIdentity)
                let before = try RuleDatabaseState(database)
                result.beforeRuleCount = before.rules.count
                let expectedBefore = action == .apply ? original : applied
                if action == .restore && before == original {
                    try database.execute("ROLLBACK")
                    result.alreadyRestored = true
                    result.verified = true
                    result.afterRuleCount = before.rules.count
                    result.detail = "当前源已与完整原始基线逻辑一致，未写入；不覆盖新内容"
                } else {
                    guard before == expectedBefore else {
                        throw PinningPreparation.failure("锁内源数据不等于预期原始/应用状态；可能有系统更新，拒绝覆盖")
                    }
                    log("受控 \(action.rawValue)：锁内基线通过，仅变更目标一行；不重载服务")
                    if action == .apply { try database.delete(row) }
                    else { try database.insert(row, rowID: rowID) }
                    guard sqlite3_changes(database.handle) == 1 else { throw PinningPreparation.failure("实际变更行数不是 1") }
                    let expectedAfter = action == .apply ? applied : original
                    guard try RuleDatabaseState(database) == expectedAfter else {
                        throw PinningPreparation.failure("提交前完整逻辑验证失败：有非目标变动")
                    }
                    try database.quickCheck()
                    try checkIdentity(path, expected: sourceIdentity)
                    var moved: Int32 = 0
                    guard sqlite3_file_control(database.handle, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK, moved == 0 else {
                        throw PinningPreparation.failure("SQLite 源文件已替换或无法确认路径身份")
                    }
                    result.commitState = .committing
                    result.detail = "准备 COMMIT；中断后结果未知，保留恢复引用，不自动覆盖"
                    try persist(result)
                    try database.execute("COMMIT")
                    result.commitState = .committed
                    result.afterRuleCount = expectedAfter.rules.count
                    result.detail = "COMMIT 成功，尚待独立读回验证"
                    try persist(result)
                    let reader = try PreparationDatabase(path: path, writable: false)
                    try reader.execute("BEGIN")
                    guard try RuleDatabaseState(reader) == expectedAfter else {
                        throw PinningPreparation.failure("COMMIT 后独立读回不符，可能有并发更新；不自动恢复")
                    }
                    try reader.quickCheck()
                    try checkPath(path, expected: sourceIdentity)
                    let after = DiagnosticEngine.inspect(path: path, sessionID: sessionID, requireRoot: requireRoot, log: log)
                    guard let afterSnapshot = after.snapshot else { throw PinningPreparation.failure("COMMIT 后快照失败") }
                    try reader.execute("ROLLBACK")
                    snapshot = afterSnapshot
                    report.database = after.report.database
                    report.hostMatches = after.report.hostMatches
                    result.verified = true
                    result.detail = "单行 COMMIT 与独立完整逻辑读回通过；未重载服务，TLS/定位未验证"
                }
            } catch {
                let originalError = error
                if sqlite3_get_autocommit(database.handle) == 0 {
                    do {
                        try database.execute("ROLLBACK")
                        if result.commitState == .notAttempted { result.commitState = .rolledBack }
                    } catch {
                        result.commitState = .unknown
                        throw PinningPreparation.failure("变更失败：\(originalError.localizedDescription)；ROLLBACK 也失败：\(error.localizedDescription)")
                    }
                }
                if result.commitState == .committing { result.commitState = .unknown }
                throw originalError
            }
            try persist(result)
            report.status = .complete
            report.checks.append(DiagnosticCheck(name: "controlled_rule_change", level: .pass, detail: result.detail))
            log(result.detail)
        } catch {
            report.status = .failed
            result.detail = "\(error.localizedDescription)；提交状态=\(result.commitState.rawValue)，保留恢复引用"
            report.checks.append(DiagnosticCheck(name: "controlled_rule_change", level: .fail, detail: result.detail))
            log("ERROR \(result.detail)")
            if !requireRoot || [report.identity.uid, report.identity.effectiveUID, report.identity.gid, report.identity.effectiveGID].allSatisfy({ $0 == 0 }) {
                do { try persist(result) }
                catch {
                    report.checks.append(DiagnosticCheck(name: "change_progress", level: .fail, detail: "变更阶段持久化失败：\(error.localizedDescription)"))
                    log("ERROR 阶段证据持久化失败：\(error.localizedDescription)")
                }
            }
        }
        report.database.writeAccess = result.commitState == .committed ? "commit_succeeded" :
            ([.committing, .unknown].contains(result.commitState) ? "commit_unknown" : "not_committed")
        report.change = result
        report.finishedAt = Date()
        return DiagnosticEnvelope(report: report, snapshot: snapshot)
    }

    @discardableResult
    private static func checkPath(_ path: String, expected: DatabaseInformation, allowDeviceChange: Bool = false) throws -> DatabaseInformation {
        var identity = expected
        identity.deviceID = try checkIdentity(path, expected: expected, allowDeviceChange: allowDeviceChange)
        for suffix in ["-wal", "-shm", "-journal"] {
            var info = stat()
            if lstat(path + suffix, &info) == 0 { throw PinningPreparation.failure("存在 sidecar \(suffix)，拒绝自动恢复/删除") }
            guard errno == ENOENT else { throw PinningPreparation.failure("无法确认 sidecar 状态：errno=\(errno)") }
        }
        return identity
    }

    @discardableResult
    private static func checkIdentity(_ path: String, expected: DatabaseInformation, allowDeviceChange: Bool = false) throws -> UInt64 {
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              expected.deviceID != nil, (allowDeviceChange || UInt64(info.st_dev) == expected.deviceID),
              UInt64(info.st_ino) == expected.fileID,
              info.st_uid == expected.ownerID, info.st_gid == expected.groupID,
              String(format: "%04o", info.st_mode & 0o7777) == expected.posixPermissions else {
            throw PinningPreparation.failure("源文件不是原始普通文件，或 device/inode/属主/权限已变化")
        }
        var parent = URL(fileURLWithPath: path).deletingLastPathComponent()
        for _ in 0..<2 {
            var node = stat()
            guard lstat(parent.path, &node) == 0, node.st_mode & S_IFMT == S_IFDIR else {
                throw PinningPreparation.failure("源父目录不是普通目录")
            }
            parent.deleteLastPathComponent()
        }
        return UInt64(info.st_dev)
    }
}
