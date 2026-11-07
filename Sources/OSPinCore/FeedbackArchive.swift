import Foundation

/// Feedback is a projection of known fields, never a copy of raw logs or database files.
public enum FeedbackArchive {
    public static func filename(date: Date = Date(), identifier: UUID = UUID()) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd-HHmmss'Z'"
        return "OSPinOverload-feedback-v\(DiagnosticAppVersion.current)-\(formatter.string(from: date))-\(identifier.uuidString.prefix(8)).zip"
    }

    public struct LogInput {
        public let source: String
        public let text: String
        public let truncated: Bool

        public init(source: String, text: String, truncated: Bool = false) {
            self.source = source
            self.text = text
            self.truncated = truncated
        }
    }

    private struct Check: Encodable {
        let name: String
        let level: CheckLevel
    }

    private struct Report: Encodable {
        let formatVersion = 1
        let appVersion = DiagnosticAppVersion.current
        let appBuild = DiagnosticAppVersion.build
        let reportAvailable: Bool
        let sourceVersion: String?
        let sourceBuild: String?
        let deviceModel: String?
        let systemVersion: String?
        let systemBuild: String?
        let operation: DiagnosticOperation?
        let status: DiagnosticStatus?
        let schemaVersion: Int64?
        let contentVersion: Int64?
        let ruleCount: Int64?
        let journalMode: String?
        let checks: [Check]
        let commitState: RuleCommitState?
        let verified: Bool?
        let recoveryPending: Bool
        let excluded = ["database", "policies", "rawLogs", "paths", "identifiers", "coordinates", "networkPayloads"]
    }

    private struct Event: Encodable {
        let source: String
        let code: String
    }

    private struct Events: Encodable {
        let formatVersion = 1
        let truncatedSources: [String]
        let entries: [Event]
    }

    public static func files(
        report: DiagnosticReport?, progress: RuleChangeResult? = nil,
        recoveryPending: Bool, logs: [LogInput] = [], operation: DiagnosticOperation? = nil
    ) throws -> [String: Data] {
        let knownChecks: Set<String> = [
            "root_identity", "device_info", "source_metadata", "sqlite_snapshot", "host_matches",
            "controlled_rule_change", "change_progress", "controller_operation", "preparation_baseline",
            "change_pending", "recovery_baseline", "offline_plan", "baseline_guard", "write_preflight",
            "file_access", "runtime_entitlement"
        ]
        let change = progress ?? report?.change
        let value = Report(
            reportAvailable: report != nil,
            sourceVersion: token(report?.appVersion, pattern: #"^\d{1,4}\.\d{1,4}\.\d{1,4}$"#),
            sourceBuild: token(report?.appBuild, pattern: #"^\d{1,8}$"#),
            deviceModel: token(report?.device.machine, pattern: #"^(?:iPhone|iPad|iPod)\d{1,3},\d{1,3}$|^(?:arm64|x86_64)$"#),
            systemVersion: systemVersionToken(report?.device.systemVersion),
            systemBuild: token(report?.device.systemBuild, pattern: #"^\d{1,3}[A-Z]\d{1,5}[a-z]?$"#),
            operation: report?.operation ?? operation, status: report?.status,
            schemaVersion: report?.database.schemaVersion, contentVersion: report?.database.contentVersion,
            ruleCount: report?.database.ruleCount,
            journalMode: ["delete", "wal", "truncate", "persist", "memory", "off"].first { $0 == report?.database.journalMode },
            checks: (report?.checks ?? []).map {
                Check(name: knownChecks.contains($0.name) ? $0.name : "other_check", level: $0.level)
            },
            commitState: change?.commitState, verified: change?.verified, recoveryPending: recoveryPending
        )
        var entries: [Event] = []
        var truncated: [String] = []
        for log in logs {
            let source = ["app", "worker", "application"].contains(log.source) ? log.source : "other"
            let lines = log.text.split(separator: "\n")
            if log.truncated || lines.count > 2000 { truncated.append(source) }
            for line in lines.suffix(2000) {
                let code: String?
                if line.contains("ERROR") && line.contains("root 验证失败") { code = "root_identity_rejected" }
                else if line.contains("ERROR") && line.contains("SQLite") { code = "sqlite_operation_failed" }
                else if line.contains("ERROR") && line.contains("恢复引用") { code = "recovery_reference_problem" }
                else if line.contains("ERROR") && line.contains("基线") { code = "baseline_verification_failed" }
                else if line.contains("ERROR") { code = "operation_error" }
                else if line.contains("posix_spawn return=0") { code = "worker_started" }
                else if line.contains("报告已持久化") { code = "report_saved" }
                else if line.contains("基线已同步落盘并校验") { code = "backup_verified" }
                else if line.contains("准备预检完成") { code = "preflight_completed" }
                else if line.contains("单行 COMMIT 与独立完整逻辑读回通过") { code = "commit_verified" }
                else if line.contains("创建 session=") { code = "operation_started" }
                else { code = nil }
                if let code { entries.append(Event(source: source, code: code)) }
            }
        }
        let notice = """
        OSPinOverload 脱敏反馈包 / Privacy-filtered feedback
        此包只包含白名单诊断字段和抽象阶段事件，不包含原始日志或任何数据库/备份。
        保留：软件版本、设备型号、系统版本、规则数量、检查名称/级别、提交阶段。
        排除：坐标、WiFi/MAC、请求/响应正文、证书策略内容、设备唯一标识、UUID、路径、原始错误详情。
        事件经过过滤，不是完整原始日志；没有事件不代表没有执行。
        本机恢复基线未被删除。请向可信接收方分享，分享前可查看反馈摘要。
        """
        return [
            "feedback.json": try DiagnosticEncoding.encoder(pretty: true).encode(value),
            "events.json": try DiagnosticEncoding.encoder(pretty: true).encode(Events(truncatedSources: truncated, entries: entries)),
            "PRIVACY.txt": Data(notice.utf8)
        ]
    }

    public static func zip(files: [String: Data]) throws -> Data {
        guard !files.isEmpty, files.count <= 16,
              files.values.reduce(0, { $0 + $1.count }) <= 4 * 1024 * 1024 else {
            throw failure("反馈内容超出安全大小限制")
        }
        var archive = Data()
        var central = Data()
        for name in files.keys.sorted() {
            guard name.utf8.count <= 128, name.range(of: #"^[A-Za-z0-9_-]+\.(?:json|txt)$"#, options: .regularExpression) != nil,
                  let bytes = files[name] else { throw failure("反馈文件名无效") }
            let nameBytes = Data(name.utf8)
            let crc = crc32(bytes), offset = UInt32(archive.count), size = UInt32(bytes.count)
            archive.le32(0x04034b50); archive.le16(20); archive.le16(0x0800); archive.le16(0)
            archive.le16(0); archive.le16(0x0021); archive.le32(crc); archive.le32(size); archive.le32(size)
            archive.le16(UInt16(nameBytes.count)); archive.le16(0)
            archive.append(nameBytes); archive.append(bytes)
            central.le32(0x02014b50); central.le16(20); central.le16(20); central.le16(0x0800); central.le16(0)
            central.le16(0); central.le16(0x0021); central.le32(crc); central.le32(size); central.le32(size)
            central.le16(UInt16(nameBytes.count)); central.le16(0); central.le16(0); central.le16(0); central.le16(0)
            central.le32(0); central.le32(offset); central.append(nameBytes)
        }
        let centralOffset = UInt32(archive.count)
        archive.append(central)
        archive.le32(0x06054b50); archive.le16(0); archive.le16(0)
        archive.le16(UInt16(files.count)); archive.le16(UInt16(files.count))
        archive.le32(UInt32(central.count)); archive.le32(centralOffset); archive.le16(0)
        return archive
    }

    static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xffffffff
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc >> 1) ^ (crc & 1 == 1 ? 0xedb88320 : 0) }
        }
        return crc ^ 0xffffffff
    }

    private static func token(_ value: String?, pattern: String) -> String? {
        guard let value, value.utf8.count <= 40, value.range(of: pattern, options: .regularExpression) != nil else { return nil }
        return value
    }

    private static func systemVersionToken(_ value: String?) -> String? {
        if let numeric = token(value, pattern: #"^\d{1,3}(?:\.\d{1,3}){0,2}$"#) { return numeric }
        guard let value, value.utf8.count <= 80 else { return nil }
        let pattern = #"^Version (\d{1,3}(?:\.\d{1,3}){0,2}) \(Build \d{1,3}[A-Z]\d{1,5}[a-z]?\)$"#
        guard let match = value.range(of: pattern, options: .regularExpression), match == value.startIndex..<value.endIndex else { return nil }
        return value.split(separator: " ").dropFirst().first.map(String.init)
    }

    private static func failure(_ text: String) -> NSError {
        NSError(domain: "OSPinOverload.Feedback", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}

private extension Data {
    mutating func le16(_ value: UInt16) {
        append(UInt8(truncatingIfNeeded: value)); append(UInt8(truncatingIfNeeded: value >> 8))
    }

    mutating func le32(_ value: UInt32) {
        le16(UInt16(truncatingIfNeeded: value)); le16(UInt16(truncatingIfNeeded: value >> 16))
    }
}
