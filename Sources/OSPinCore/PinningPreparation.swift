import CryptoKit
import Darwin
import Foundation
import SQLite3

public struct RawPinningRule: Codable {
    public let policyName: String
    public let domainSuffix: String
    public let labelRegex: String
    public let policies: Data
    public let transparentConnection: Int64?

    public func fingerprint() throws -> String {
        PinningPreparation.sha256(try DiagnosticEncoding.encoder().encode(self))
    }
}

public struct PreparationResult: Codable {
    public let baselineSHA256: String
    public let baselineMetadataSHA256: String
    public var readWriteOpened: Bool?
    public var transactionBegan: Bool?
    public var rollbackSucceeded: Bool?
    public var sourceUnchanged: Bool?
    public let actualWriteCommitted: Bool
    public var offlinePlan: OfflinePinningPlan?
}

public enum DiagnosticWorkerRequest: Equatable {
    case diagnose(UUID)
    case prepare(UUID, String, String)
    case permissions(UUID, FileAccessProfile)
    case change(UUID, DiagnosticOperation, UUID, String)

    public static func parse(_ arguments: [String]) -> DiagnosticWorkerRequest? {
        guard arguments.count >= 2, let id = UUID(uuidString: arguments[1]) else { return nil }
        if arguments == ["--diagnose", arguments[1]] { return .diagnose(id) }
        if arguments.count == 4, ["--apply", "--restore"].contains(arguments[0]),
           let baselineID = UUID(uuidString: arguments[2]),
           arguments[3].utf8.count == 64,
           arguments[3].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) {
            return .change(id, arguments[0] == "--apply" ? .apply : .restore, baselineID, arguments[3])
        }
        if arguments.count == 3, arguments[0] == "--permissions",
           let profile = FileAccessProfile(rawValue: arguments[2]) {
            return .permissions(id, profile)
        }
        if arguments.count == 4, arguments[0] == "--prepare",
           arguments[2...3].allSatisfy({ $0.utf8.count == 64 && $0.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) }) {
            return .prepare(id, arguments[2], arguments[3])
        }
        return nil
    }
}

public struct RecoveryBaselineReceipt: Codable {
    public let baselineFormatVersion: Int
    public let appVersion: String
    public let appBuild: String
    public let sessionID: UUID
    public let createdAt: Date
    public let database: DatabaseInformation
    public let files: [ExportedDiagnosticFile]
}

public enum RecoveryBaselineStore {
    public static let fileNames = ["baseline.sqlite3", "baseline-report.json", "baseline-receipt.json"]

    public static func save(_ envelope: DiagnosticEnvelope, directory: URL) throws -> RecoveryBaselineReceipt {
        guard envelope.report.status == .complete, let snapshot = envelope.snapshot,
              snapshot.count > 0, snapshot.count <= SQLitePinningReader.defaultSnapshotLimit,
              snapshot.count == envelope.report.database.snapshotByteCount,
              PinningPreparation.sha256(snapshot) == envelope.report.database.snapshotSHA256,
              envelope.report.appVersion == DiagnosticAppVersion.current,
              envelope.report.appBuild == DiagnosticAppVersion.build,
              !FileManager.default.fileExists(atPath: directory.path) else {
            throw PinningPreparation.failure("基线来源/摘要不完整或目录已存在；拒绝覆盖")
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let report = try DiagnosticEncoding.encoder(pretty: true).encode(envelope.report)
        var files: [ExportedDiagnosticFile] = []
        for (name, bytes) in [("baseline.sqlite3", snapshot), ("baseline-report.json", report)] {
            try persist(bytes, url: directory.appendingPathComponent(name))
            files.append(ExportedDiagnosticFile(name: name, byteCount: UInt64(bytes.count), sha256: PinningPreparation.sha256(bytes)))
        }
        let receipt = RecoveryBaselineReceipt(
            baselineFormatVersion: 1, appVersion: DiagnosticAppVersion.current, appBuild: DiagnosticAppVersion.build,
            sessionID: envelope.report.sessionID, createdAt: Date(), database: envelope.report.database, files: files
        )
        try persist(try DiagnosticEncoding.encoder(pretty: true).encode(receipt),
                    url: directory.appendingPathComponent("baseline-receipt.json"))
        try verify(directory: directory, sessionID: envelope.report.sessionID)
        return receipt
    }

    public static func verify(directory: URL, sessionID: UUID, requireCurrentBuild: Bool = true) throws {
        for name in fileNames {
            let attributes = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(name).path)
            let limit = name == "baseline-receipt.json" ? 64 * 1024 : SQLitePinningReader.defaultSnapshotLimit
            guard attributes[.type] as? FileAttributeType == .typeRegular,
                  let size = attributes[.size] as? NSNumber, size.int64Value <= Int64(limit) else {
                throw PinningPreparation.failure("基线包含非普通文件：\(name)")
            }
        }
        let receipt = try DiagnosticEncoding.decoder().decode(
            RecoveryBaselineReceipt.self, from: Data(contentsOf: directory.appendingPathComponent("baseline-receipt.json"))
        )
        guard receipt.baselineFormatVersion == 1, receipt.sessionID == sessionID,
              (!requireCurrentBuild || (receipt.appVersion == DiagnosticAppVersion.current && receipt.appBuild == DiagnosticAppVersion.build)),
              receipt.files.map(\.name).sorted() == ["baseline-report.json", "baseline.sqlite3"] else {
            throw PinningPreparation.failure("基线清单标识不一致")
        }
        for file in receipt.files {
            let data = try Data(contentsOf: directory.appendingPathComponent(file.name))
            guard UInt64(data.count) == file.byteCount, PinningPreparation.sha256(data) == file.sha256 else {
                throw PinningPreparation.failure("恢复基线校验失败：\(file.name)")
            }
        }
        let report = try DiagnosticEncoding.decoder().decode(
            DiagnosticReport.self, from: Data(contentsOf: directory.appendingPathComponent("baseline-report.json"))
        )
        guard report.sessionID == sessionID, report.appVersion == receipt.appVersion,
              report.appBuild == receipt.appBuild,
              report.status == .complete,
              try DiagnosticEncoding.encoder().encode(report.database) == DiagnosticEncoding.encoder().encode(receipt.database),
              receipt.files.first(where: { $0.name == "baseline.sqlite3" })?.sha256 == receipt.database.snapshotSHA256 else {
            throw PinningPreparation.failure("基线报告与快照不一致")
        }
    }

    private static func persist(_ bytes: Data, url: URL) throws {
        try bytes.write(to: url, options: .atomic)
        let handle = try FileHandle(forWritingTo: url)
        do {
            try handle.synchronize()
            try handle.close()
        } catch {
            try handle.close()
            throw error
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o400], ofItemAtPath: url.path)
    }
}

public struct OfflinePinningPlan: Codable {
    public let planFormatVersion: Int
    public let appVersion: String
    public let appBuild: String
    public let sessionID: UUID
    public let baselineSHA256: String
    public let targetRuleFingerprint: String
    public let targetHosts: [String]
    public let restoreRule: RawPinningRule
    public let originalRuleCount: Int
    public let candidateRuleCount: Int
    public let candidateSHA256: String
    public let restoredSHA256: String
    public let logicalRestoreVerified: Bool
    public let activeDatabaseModified: Bool
    public let warning: String
}

public enum PinningPreparation {
    public static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func preflight(
        path: String = DiagnosticEngine.protectedDatabasePath,
        sessionID: UUID,
        baselineSHA256: String,
        baselineMetadataSHA256: String,
        requireRoot: Bool = true,
        log: (String) -> Void
    ) -> DiagnosticEnvelope {
        let envelope = DiagnosticEngine.inspect(path: path, sessionID: sessionID, requireRoot: requireRoot, log: log)
        var report = envelope.report
        report.operation = .prepare
        var result = PreparationResult(
            baselineSHA256: baselineSHA256, baselineMetadataSHA256: baselineMetadataSHA256,
            readWriteOpened: nil, transactionBegan: nil,
            rollbackSucceeded: nil, sourceUnchanged: nil, actualWriteCommitted: false, offlinePlan: nil
        )
        do {
            guard report.status == .complete, let snapshot = envelope.snapshot,
                  sha256(snapshot) == baselineSHA256,
                  sha256(try DiagnosticEncoding.encoder().encode(report.database)) == baselineMetadataSHA256 else {
                throw failure("恢复基线与当前数据库不一致，或只读诊断未完成；未开始写入预检")
            }
            _ = try targetRule(in: report)
            guard report.database.schemaVersion == 3, report.database.journalMode == "delete" else {
                throw failure("准备模式仅支持已验证的 schema 3 / DELETE journal；未进行预检")
            }
            for suffix in ["-journal", "-wal", "-shm"] {
                guard !FileManager.default.fileExists(atPath: path + suffix) else {
                    throw failure("检测到 SQLite sidecar \(suffix)，为避免恢复/协调副作用停止预检")
                }
            }
            report.checks.append(DiagnosticCheck(name: "baseline_guard", level: .pass, detail: "当前快照与已保存基线一致"))
            let sourceIdentity = try metadataIdentity(path)
            let expectedIdentity: [UInt64?] = [
                report.database.deviceID, report.database.fileID,
                report.database.ownerID.map { UInt64($0) }, report.database.groupID.map { UInt64($0) },
                report.database.posixPermissions.flatMap { UInt64($0, radix: 8) },
                report.database.fileSize.flatMap { UInt64(exactly: $0) }
            ]
            guard expectedIdentity.compactMap({ $0 }).count == 6,
                  sourceIdentity == expectedIdentity.compactMap({ $0 }) else {
                throw failure("只读快照之后源文件身份或权限已变化；未开始读写预检")
            }
            log("准备预检：打开 READWRITE，不使用 CREATE；仅 BEGIN IMMEDIATE / ROLLBACK，不执行规则写入")
            result.readWriteOpened = false
            let database = try PreparationDatabase(path: path, writable: true)
            try database.validateLayout()
            let authorizerCode = sqlite3_set_authorizer(database.handle, { _, action, _, _, _, _ in
                switch action {
                case SQLITE_SELECT, SQLITE_READ, SQLITE_TRANSACTION, SQLITE_FUNCTION, SQLITE_PRAGMA:
                    return SQLITE_OK
                default: return SQLITE_DENY
                }
            }, nil)
            guard authorizerCode == SQLITE_OK else { throw failure("SQLite 禁止写入的 authorizer 设置失败：\(authorizerCode)") }
            result.readWriteOpened = sqlite3_db_readonly(database.handle, "main") == 0
            guard result.readWriteOpened == true else { throw failure("SQLite 连接仍为只读") }
            result.transactionBegan = false
            try database.execute("BEGIN IMMEDIATE")
            result.transactionBegan = true
            do {
                let locked = try SQLitePinningReader().capture(path: path, hosts: DiagnosticEngine.targetHosts, log: log)
                guard sha256(locked.snapshot) == baselineSHA256 else {
                    throw failure("获取事务锁后基线已变化；停止预检")
                }
                result.rollbackSucceeded = false
                try database.execute("ROLLBACK")
                result.rollbackSucceeded = true
            } catch {
                if sqlite3_get_autocommit(database.handle) == 0 {
                    do {
                        result.rollbackSucceeded = false
                        try database.execute("ROLLBACK")
                        result.rollbackSucceeded = true
                    } catch let rollbackError {
                        throw failure("预检失败：\(error.localizedDescription)；ROLLBACK 失败：\(rollbackError.localizedDescription)")
                    }
                }
                throw error
            }
            let after = try SQLitePinningReader().capture(path: path, hosts: DiagnosticEngine.targetHosts, log: log)
            let afterIdentity = try metadataIdentity(path)
            result.sourceUnchanged = sha256(after.snapshot) == baselineSHA256 && afterIdentity == sourceIdentity
            guard result.sourceUnchanged == true else {
                throw failure("预检后数据库与基线不同，可能存在并发系统更新；不自动恢复或继续")
            }
            report.checks.append(DiagnosticCheck(
                name: "write_preflight", level: .pass,
                detail: "READWRITE、BEGIN IMMEDIATE、ROLLBACK 通过，前后快照一致；实际写入提交仍未测试"
            ))
            log("准备预检完成：已回滚，源快照未变；不证明实际 COMMIT 可用，不重载 trustd")
        } catch {
            report.status = .failed
            report.checks.append(DiagnosticCheck(name: "write_preflight", level: .fail, detail: error.localizedDescription))
            log("ERROR 准备预检停止：\(error.localizedDescription)")
        }
        report.preparation = result
        report.finishedAt = Date()
        return DiagnosticEnvelope(report: report, snapshot: envelope.snapshot)
    }

    public static func targetRule(in report: DiagnosticReport) throws -> PinningRule {
        guard report.hostMatches.map(\.hostname) == DiagnosticEngine.targetHosts,
              report.hostMatches.allSatisfy({ $0.rules.count == 1 }),
              let first = report.hostMatches.first?.rules.first,
              first.policyName == "AppleIssued", first.domainSuffix == "apple.com",
              first.labelRegex == "^gs-loc$|^gs-loc-cn$",
              first.transparentConnection == nil || first.transparentConnection == 0,
              let fingerprint = first.sourceFingerprint,
              report.hostMatches.allSatisfy({ $0.rules[0].sourceFingerprint == fingerprint }) else {
            throw failure("目标规则不是已验证的单条共享 AppleIssued 规则；不猜测候选改动")
        }
        return first
    }

    public static func createOfflinePlan(
        snapshot: Data, report: DiagnosticReport, directory: URL
    ) throws -> OfflinePinningPlan {
        guard let expectedHash = report.database.snapshotSHA256,
              sha256(snapshot) == expectedHash, report.database.schemaVersion == 3,
              report.database.journalMode == "delete" else {
            throw failure("离线基线摘要、schema 3 或 DELETE journal 校验失败")
        }
        let target = try targetRule(in: report)
        let resolved = directory.standardizedFileURL.resolvingSymlinksInPath().path
        guard !resolved.hasPrefix("/private/var/protected/"), !resolved.hasPrefix("/var/protected/"),
              !FileManager.default.fileExists(atPath: directory.path) else {
            throw failure("离线输出必须是新的非系统目录")
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let candidate = directory.appendingPathComponent("candidate.sqlite3")
        try snapshot.write(to: candidate, options: .atomic)
        let database = try PreparationDatabase(path: candidate.path, writable: true)
        try database.validateLayout()
        let originalRowID = try database.targetRowID()
        let beforeSchema = try database.rows("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
        let beforeAdmin = try database.rows("SELECT * FROM admin")
        let beforeRules = try database.rows("SELECT rowid,* FROM rules")
        let beforeUnrelated = try database.rows("SELECT rowid,* FROM rules WHERE NOT (policyName='AppleIssued' AND domainSuffix='apple.com' AND labelRegex='^gs-loc$|^gs-loc-cn$')")
        let rows = try database.targetRows()
        guard rows.count == 1, let row = rows.first, try row.fingerprint() == target.sourceFingerprint else {
            throw failure("离线副本目标行指纹不一致")
        }
        try database.execute("BEGIN IMMEDIATE")
        do {
            try database.delete(row)
            guard sqlite3_changes(database.handle) == 1 else { throw failure("离线删除行数不是 1") }
            try database.execute("COMMIT")
        } catch {
            if sqlite3_get_autocommit(database.handle) == 0 { try database.execute("ROLLBACK") }
            throw error
        }
        let candidateRules = try database.rows("SELECT rowid,* FROM rules")
        let targetRows = try database.rows("SELECT * FROM rules WHERE policyName='AppleIssued' AND domainSuffix='apple.com' AND labelRegex='^gs-loc$|^gs-loc-cn$'")
        guard targetRows.isEmpty, beforeRules.count == candidateRules.count + 1,
              try database.rows("SELECT * FROM admin") == beforeAdmin,
              try database.rows("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name") == beforeSchema else {
            throw failure("候选副本存在非预期变动")
        }
        guard candidateRules == beforeUnrelated else { throw failure("候选副本改变了非目标规则") }
        try database.quickCheck()
        let candidateBytes = try Data(contentsOf: candidate)
        let restored = directory.appendingPathComponent("restored.sqlite3")
        try candidateBytes.write(to: restored, options: .atomic)
        let restore = try PreparationDatabase(path: restored.path, writable: true)
        try restore.insert(row, rowID: originalRowID)
        try restore.quickCheck()
        guard try restore.rows("SELECT rowid,* FROM rules") == beforeRules,
              try restore.rows("SELECT * FROM admin") == beforeAdmin,
              try restore.rows("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name") == beforeSchema else {
            throw failure("离线恢复演练未恢复完整逻辑基线")
        }
        let plan = OfflinePinningPlan(
            planFormatVersion: 1, appVersion: DiagnosticAppVersion.current, appBuild: DiagnosticAppVersion.build,
            sessionID: report.sessionID, baselineSHA256: expectedHash, targetRuleFingerprint: try row.fingerprint(),
            targetHosts: DiagnosticEngine.targetHosts, restoreRule: row, originalRuleCount: beforeRules.count,
            candidateRuleCount: candidateRules.count, candidateSHA256: sha256(candidateBytes),
            restoredSHA256: sha256(try Data(contentsOf: restored)), logicalRestoreVerified: true,
            activeDatabaseModified: false,
            warning: "仅副本移除一条定位 hostname 规则并恢复；未应用到系统，不能保证绕过额外固定策略或恢复定位。"
        )
        try DiagnosticEncoding.encoder(pretty: true).encode(plan)
            .write(to: directory.appendingPathComponent("plan.json"), options: .atomic)
        return plan
    }

    static func failure(_ message: String) -> NSError {
        NSError(domain: "OSPinOverload.Preparation", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private static func metadataIdentity(_ path: String) throws -> [UInt64] {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        return try [.systemNumber, .systemFileNumber, .ownerAccountID, .groupOwnerAccountID, .posixPermissions, .size]
            .map { (key: FileAttributeKey) in
                guard let value = attributes[key] as? NSNumber else { throw failure("无法确认源文件元数据：\(key.rawValue)") }
                return value.uint64Value
            }
    }
}

final class PreparationDatabase {
    let handle: OpaquePointer
    private let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    init(path: String, writable: Bool) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw PinningPreparation.failure("数据库不是普通文件")
        }
        var database: OpaquePointer?
        // Foundation can normalize /private/var back to /var; SQLite NOFOLLOW needs realpath.
        guard let canonicalPath = realpath(path, nil) else { throw PinningPreparation.failure("realpath 失败：errno=\(errno)") }
        defer { free(canonicalPath) }
        let code = sqlite3_open_v2(canonicalPath, &database, (writable ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY) | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil)
        guard code == SQLITE_OK, let database else {
            let detail = database.map { String(cString: sqlite3_errmsg($0)) } ?? "无法打开"
            if let database { sqlite3_close(database) }
            throw PinningPreparation.failure("SQLite open (\(code)): \(detail)")
        }
        handle = database
        sqlite3_busy_timeout(handle, 1_000)
    }

    deinit { sqlite3_close(handle) }

    func execute(_ sql: String) throws {
        let code = sqlite3_exec(handle, sql, nil, nil, nil)
        guard code == SQLITE_OK else { throw error(code) }
    }

    func rows(_ sql: String) throws -> [String] { try Self.readRows(handle, sql) }

    static func readRows(_ handle: OpaquePointer, _ sql: String) throws -> [String] {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            if let statement { sqlite3_finalize(statement) }
            throw PinningPreparation.failure("SQLite query: \(String(cString: sqlite3_errmsg(handle)))")
        }
        defer { sqlite3_finalize(statement) }
        var rows: [String] = []
        while true {
            let code = sqlite3_step(statement)
            if code == SQLITE_DONE { break }
            guard code == SQLITE_ROW else { throw PinningPreparation.failure("SQLite row (\(code)): \(String(cString: sqlite3_errmsg(handle)))") }
            var values: [String] = []
            for index in 0..<sqlite3_column_count(statement) {
                let type = sqlite3_column_type(statement, index)
                if type == SQLITE_NULL { values.append("null"); continue }
                let count = Int(sqlite3_column_bytes(statement, index))
                let bytes = sqlite3_column_blob(statement, index)
                let data = bytes.map { Data(bytes: $0, count: count) } ?? Data()
                values.append("\(type):\(data.base64EncodedString())")
            }
            rows.append(values.joined(separator: "|"))
        }
        return rows.sorted()
    }

    func targetRows() throws -> [RawPinningRule] {
        let statement = try prepare("SELECT policyName,domainSuffix,labelRegex,policies,transparentConnection FROM rules WHERE policyName='AppleIssued' AND domainSuffix='apple.com' AND labelRegex='^gs-loc$|^gs-loc-cn$'")
        defer { sqlite3_finalize(statement) }
        var result: [RawPinningRule] = []
        while true {
            let code = sqlite3_step(statement)
            if code == SQLITE_DONE { return result }
            guard code == SQLITE_ROW else { throw error(code) }
            let length = Int(sqlite3_column_bytes(statement, 3))
            guard length > 0, sqlite3_column_type(statement, 3) == SQLITE_BLOB,
                  [SQLITE_INTEGER, SQLITE_NULL].contains(sqlite3_column_type(statement, 4)),
                  let bytes = sqlite3_column_blob(statement, 3) else { throw PinningPreparation.failure("目标 policies/transparentConnection 类型无效") }
            result.append(RawPinningRule(
                policyName: text(statement, 0), domainSuffix: text(statement, 1), labelRegex: text(statement, 2),
                policies: Data(bytes: bytes, count: length),
                transparentConnection: sqlite3_column_type(statement, 4) == SQLITE_NULL ? nil : sqlite3_column_int64(statement, 4)
            ))
        }
    }

    func delete(_ row: RawPinningRule) throws {
        try change("DELETE FROM rules WHERE policyName=? AND domainSuffix=? AND labelRegex=? AND policies=? AND transparentConnection IS ?", row)
    }

    func insert(_ row: RawPinningRule, rowID: Int64? = nil) throws {
        try change(rowID == nil
            ? "INSERT INTO rules(policyName,domainSuffix,labelRegex,policies,transparentConnection) VALUES(?,?,?,?,?)"
            : "INSERT INTO rules(policyName,domainSuffix,labelRegex,policies,transparentConnection,rowid) VALUES(?,?,?,?,?,?)", row, rowID: rowID)
    }

    func targetRowID() throws -> Int64 {
        let statement = try prepare("SELECT rowid FROM rules WHERE policyName='AppleIssued' AND domainSuffix='apple.com' AND labelRegex='^gs-loc$|^gs-loc-cn$'")
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw PinningPreparation.failure("目标 rowid 不存在") }
        let result = sqlite3_column_int64(statement, 0)
        guard sqlite3_step(statement) == SQLITE_DONE else { throw PinningPreparation.failure("目标 rowid 不唯一") }
        return result
    }

    func ruleColumnNames() throws -> [String] {
        let statement = try prepare("PRAGMA table_xinfo(rules)")
        defer { sqlite3_finalize(statement) }
        var result: [String] = []
        while true {
            let code = sqlite3_step(statement)
            if code == SQLITE_DONE { return result }
            guard code == SQLITE_ROW, sqlite3_column_type(statement, 1) == SQLITE_TEXT,
                  sqlite3_column_int(statement, 6) == 0 else {
                throw PinningPreparation.failure("不支持隐藏列或生成列")
            }
            result.append(text(statement, 1))
        }
    }

    func validateLayout() throws {
        let tables = try rows("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        guard tables == ["admin", "rules"].map({ "3:\(Data($0.utf8).base64EncodedString())" }).sorted(),
              try rows("SELECT name FROM sqlite_master WHERE type NOT IN ('table','index')").isEmpty,
              Set(try ruleColumnNames()) == Set(["policyName", "domainSuffix", "labelRegex", "policies", "transparentConnection"]),
              try rows("PRAGMA user_version") == ["1:Mw=="],
              try rows("PRAGMA journal_mode") == ["3:ZGVsZXRl"] else {
            throw PinningPreparation.failure("当前数据库不支持安全修改；需 schema 3、DELETE journal、已知五列及 admin/rules，无 trigger/view")
        }
        _ = try rows("SELECT rowid,* FROM rules LIMIT 1")
        _ = try rows("SELECT rowid,* FROM admin LIMIT 1")
    }

    func quickCheck() throws {
        let statement = try prepare("PRAGMA quick_check")
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW, text(statement, 0) == "ok" else {
            throw PinningPreparation.failure("离线完整性检查失败")
        }
    }

    private func change(_ sql: String, _ row: RawPinningRule, rowID: Int64? = nil) throws {
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        for (index, value) in [row.policyName, row.domainSuffix, row.labelRegex].enumerated() {
            guard sqlite3_bind_text(statement, Int32(index + 1), value, -1, transient) == SQLITE_OK else { throw error(sqlite3_errcode(handle)) }
        }
        let blobCode = row.policies.withUnsafeBytes { sqlite3_bind_blob(statement, 4, $0.baseAddress, Int32($0.count), transient) }
        guard blobCode == SQLITE_OK else { throw error(blobCode) }
        let valueCode = row.transparentConnection.map { sqlite3_bind_int64(statement, 5, $0) } ?? sqlite3_bind_null(statement, 5)
        guard valueCode == SQLITE_OK else { throw error(valueCode) }
        if let rowID {
            guard sqlite3_bind_int64(statement, 6, rowID) == SQLITE_OK else { throw error(sqlite3_errcode(handle)) }
        }
        let code = sqlite3_step(statement)
        guard code == SQLITE_DONE else { throw error(code) }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        var statement: OpaquePointer?
        let code = sqlite3_prepare_v2(handle, sql, -1, &statement, nil)
        guard code == SQLITE_OK, let statement else {
            if let statement { sqlite3_finalize(statement) }
            throw error(code)
        }
        return statement
    }

    private func text(_ statement: OpaquePointer, _ column: Int32) -> String {
        String(cString: sqlite3_column_text(statement, column))
    }

    private func error(_ code: Int32) -> NSError {
        PinningPreparation.failure("SQLite (\(code)): \(String(cString: sqlite3_errmsg(handle)))")
    }
}
