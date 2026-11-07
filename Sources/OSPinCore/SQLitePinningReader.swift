import CryptoKit
import Foundation
import SQLite3

enum PinningReaderError: LocalizedError {
    case sqlite(String)
    case invalidData(String)
    case snapshotTooLarge
    case backupTimedOut

    var errorDescription: String? {
        switch self {
        case .sqlite(let message): return "SQLite: \(message)"
        case .invalidData(let message): return "规则格式无效：\(message)"
        case .snapshotTooLarge: return "数据库快照超过允许大小，已停止读取"
        case .backupTimedOut: return "SQLite 一致性备份超时"
        }
    }
}

struct PinningCapture {
    let schemaVersion: Int64
    let contentVersion: Int64
    let ruleCount: Int64
    let journalMode: String
    let matches: [HostRuleMatch]
    let snapshot: Data
}

final class SQLitePinningReader {
    static let defaultSnapshotLimit = 16 * 1024 * 1024
    private let maximumSnapshotBytes: Int

    init(maximumSnapshotBytes: Int = defaultSnapshotLimit) {
        self.maximumSnapshotBytes = maximumSnapshotBytes
    }

    func capture(path: String, hosts: [String], log: (String) -> Void) throws -> PinningCapture {
        var source: OpaquePointer?
        let openResult = sqlite3_open_v2(path, &source, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard openResult == SQLITE_OK, let source else {
            let message = source.map { String(cString: sqlite3_errmsg($0)) } ?? "无法打开数据库"
            if let source { sqlite3_close(source) }
            throw PinningReaderError.sqlite("open read-only (\(openResult)): \(message)")
        }
        defer { sqlite3_close(source) }
        guard sqlite3_db_readonly(source, "main") == 1 else {
            throw PinningReaderError.sqlite("源连接不是只读连接")
        }
        sqlite3_busy_timeout(source, 2_000)
        log("SQLite 源连接已使用 SQLITE_OPEN_READONLY 打开；不测试写权限")

        let pageSize = try integer(source, "PRAGMA page_size")
        let estimatedBytes = try integer(source, "PRAGMA page_count") * pageSize
        guard maximumSnapshotBytes > 0, estimatedBytes <= Int64(maximumSnapshotBytes) else {
            throw PinningReaderError.snapshotTooLarge
        }
        let journalMode = try text(source, "PRAGMA journal_mode")

        var destination: OpaquePointer?
        guard sqlite3_open(":memory:", &destination) == SQLITE_OK, let destination else {
            if let destination { sqlite3_close(destination) }
            throw PinningReaderError.sqlite("无法创建内存快照")
        }
        defer { sqlite3_close(destination) }

        guard let backup = sqlite3_backup_init(destination, "main", source, "main") else {
            throw PinningReaderError.sqlite(String(cString: sqlite3_errmsg(destination)))
        }
        let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
        var stepResult: Int32 = SQLITE_OK
        var backupFailure: Error?
        repeat {
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                backupFailure = PinningReaderError.backupTimedOut
                break
            }
            stepResult = sqlite3_backup_step(backup, 64)
            if stepResult == SQLITE_BUSY || stepResult == SQLITE_LOCKED {
                Thread.sleep(forTimeInterval: 0.02)
            }
            if Int64(sqlite3_backup_pagecount(backup)) * pageSize > Int64(maximumSnapshotBytes) {
                backupFailure = PinningReaderError.snapshotTooLarge
                break
            }
        } while stepResult == SQLITE_OK || stepResult == SQLITE_BUSY || stepResult == SQLITE_LOCKED
        let finishResult = sqlite3_backup_finish(backup)
        if let backupFailure { throw backupFailure }
        guard stepResult == SQLITE_DONE, finishResult == SQLITE_OK else {
            throw PinningReaderError.sqlite("backup (\(stepResult)/\(finishResult)): \(String(cString: sqlite3_errmsg(destination)))")
        }
        log("SQLite backup API 已生成一致性内存快照；未直接复制活动数据库或 WAL")

        guard try text(destination, "PRAGMA quick_check") == "ok" else {
            throw PinningReaderError.invalidData("快照 quick_check 未通过")
        }
        let schemaVersion = try integer(destination, "PRAGMA user_version")
        let contentVersion = try integer(destination, "SELECT ival FROM admin WHERE key='version'")
        let ruleCount = try integer(destination, "SELECT count(*) FROM rules")
        let matches = try hosts.map { host in
            HostRuleMatch(hostname: host, rules: try rules(database: destination, hostname: host))
        }
        var byteCount: sqlite3_int64 = 0
        guard let bytes = sqlite3_serialize(destination, "main", &byteCount, 0) else {
            throw PinningReaderError.sqlite("无法序列化一致性快照")
        }
        defer { sqlite3_free(bytes) }
        guard byteCount > 0, byteCount <= Int64(maximumSnapshotBytes) else {
            throw PinningReaderError.snapshotTooLarge
        }
        let snapshot = Data(bytes: bytes, count: Int(byteCount))
        log("快照完整性检查通过，schema=\(schemaVersion)，content=\(contentVersion)，rules=\(ruleCount)，bytes=\(byteCount)")
        return PinningCapture(
            schemaVersion: schemaVersion, contentVersion: contentVersion,
            ruleCount: ruleCount, journalMode: journalMode, matches: matches, snapshot: snapshot
        )
    }

    private func rules(database: OpaquePointer, hostname: String) throws -> [PinningRule] {
        guard let dot = hostname.firstIndex(of: ".") else {
            throw PinningReaderError.invalidData("主机名没有域名后缀")
        }
        let label = String(hostname[..<dot])
        var suffix = String(hostname[hostname.index(after: dot)...])
        if suffix.hasSuffix(".") { suffix.removeLast() }
        let sql = """
        SELECT DISTINCT policyName,domainSuffix,labelRegex,policies,transparentConnection
        FROM rules WHERE domainSuffix=? ORDER BY policyName,labelRegex
        """
        let statement = try prepare(database, sql)
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        guard sqlite3_bind_text(statement, 1, suffix, -1, transient) == SQLITE_OK else {
            throw PinningReaderError.sqlite(String(cString: sqlite3_errmsg(database)))
        }
        var result: [PinningRule] = []
        while true {
            let code = sqlite3_step(statement)
            if code == SQLITE_DONE { break }
            guard code == SQLITE_ROW else {
                throw PinningReaderError.sqlite(String(cString: sqlite3_errmsg(database)))
            }
            let pattern = try columnText(statement, 2)
            let regex = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
            guard regex.numberOfMatches(in: label, range: NSRange(label.startIndex..., in: label)) > 0 else {
                continue
            }
            let length = Int(sqlite3_column_bytes(statement, 3))
            guard length > 0, let bytes = sqlite3_column_blob(statement, 3) else {
                throw PinningReaderError.invalidData("policies 为空")
            }
            let policyData = Data(bytes: bytes, count: length)
            let plist = try PropertyListSerialization.propertyList(from: policyData, options: [], format: nil)
            guard let policies = plist as? [[String: Any]], !policies.isEmpty else {
                throw PinningReaderError.invalidData("policies 必须是非空字典数组")
            }
            let xml = try PropertyListSerialization.data(fromPropertyList: policies, format: .xml, options: 0)
            let json = try JSONSerialization.data(
                withJSONObject: jsonValue(policies), options: [.prettyPrinted, .sortedKeys]
            )
            guard let xmlString = String(data: xml, encoding: .utf8),
                  let jsonString = String(data: json, encoding: .utf8) else {
                throw PinningReaderError.invalidData("策略文本编码失败")
            }
            let row = RawPinningRule(
                policyName: try columnText(statement, 0),
                domainSuffix: try columnText(statement, 1), labelRegex: pattern, policies: policyData,
                transparentConnection: sqlite3_column_type(statement, 4) == SQLITE_NULL ? nil : sqlite3_column_int64(statement, 4)
            )
            result.append(PinningRule(
                policyName: row.policyName, domainSuffix: row.domainSuffix, labelRegex: pattern,
                transparentConnection: row.transparentConnection,
                policiesPropertyListXML: xmlString, policiesJSON: jsonString, sourceFingerprint: try row.fingerprint()
            ))
        }
        return result
    }

    private func jsonValue(_ value: Any) -> Any {
        if let data = value as? Data {
            return ["type": "data", "hex": data.map { String(format: "%02x", $0) }.joined()]
        }
        if let date = value as? Date { return ISO8601DateFormatter().string(from: date) }
        if let array = value as? [Any] { return array.map(jsonValue) }
        if let dictionary = value as? [String: Any] { return dictionary.mapValues(jsonValue) }
        return value
    }

    private func prepare(_ database: OpaquePointer, _ sql: String) throws -> OpaquePointer {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
            if let statement { sqlite3_finalize(statement) }
            throw PinningReaderError.sqlite(String(cString: sqlite3_errmsg(database)))
        }
        return statement
    }

    private func integer(_ database: OpaquePointer, _ sql: String) throws -> Int64 {
        let statement = try prepare(database, sql)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw PinningReaderError.sqlite("\(sql): \(String(cString: sqlite3_errmsg(database)))")
        }
        guard sqlite3_column_type(statement, 0) == SQLITE_INTEGER else {
            throw PinningReaderError.invalidData("\(sql) 没有返回整数")
        }
        return sqlite3_column_int64(statement, 0)
    }

    private func text(_ database: OpaquePointer, _ sql: String) throws -> String {
        let statement = try prepare(database, sql)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw PinningReaderError.sqlite("\(sql): \(String(cString: sqlite3_errmsg(database)))")
        }
        return try columnText(statement, 0)
    }

    private func columnText(_ statement: OpaquePointer, _ index: Int32) throws -> String {
        guard sqlite3_column_type(statement, index) == SQLITE_TEXT,
              let text = sqlite3_column_text(statement, index) else {
            throw PinningReaderError.invalidData("第 \(index) 列不是文本")
        }
        return String(cString: text)
    }
}
