import CryptoKit
import Darwin
import Foundation

public enum DiagnosticEngine {
    public static let protectedDatabasePath = "/private/var/protected/trustd/pinningrules.sqlite3"
    public static let targetHosts = ["gs-loc.apple.com", "gs-loc-cn.apple.com"]

    public static func initialReport(
        sessionID: UUID, path: String = protectedDatabasePath, operation: DiagnosticOperation = .diagnose
    ) -> DiagnosticReport {
        let startedAt = Date()
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return DiagnosticReport(
            reportFormatVersion: 1, appVersion: DiagnosticAppVersion.current,
            appBuild: DiagnosticAppVersion.build, sessionID: sessionID,
            startedAt: startedAt, finishedAt: startedAt, status: .failed,
            identity: ProcessIdentity(
                uid: getuid(), effectiveUID: geteuid(), gid: getgid(), effectiveGID: getegid(), pid: getpid()
            ),
            device: DeviceInformation(
                machine: systemValue("hw.machine"),
                systemVersion: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
                systemBuild: systemValue("kern.osversion")
            ),
            database: DatabaseInformation(sourcePath: path, writeAccess: "not_tested"),
            checks: [], hostMatches: [], preparation: nil, operation: operation,
            limitations: operation == .permissions ? [
                "只采集元数据并 open(O_RDWR) 后关闭；不读写文件内容，不调用 SQLite，不创建 sidecar，不修改权限、属主或标志。",
                "UID/GID 282 不等于 trustd 的进程身份、entitlements 或 MAC 授权。",
                "本版只新增 storage.trustd 声明；自身内核签名查询的 Boolean 不是文件系统授权决策，也不代表 COMMIT 可用。",
                "打开成功不证明实际写入、目录创建 journal、SQLite COMMIT 或定位恢复可用。",
                "前后只比较元数据，不进行内容哈希；不读取 ACL 或内核 MAC 规则，不能仅凭 errno 判定保护机制。"
            ] : [
                "诊断模式只读，准备模式只回滚；应用/恢复模式会在用户确认后提交单条规则变更，不重启服务、不阻止更新。",
                "只查询 hostname 规则；无法确定 locationd 的实际策略名称或 TLS 验证结果。",
                "contentVersion 是数据库内容版本，不等同于设置中的信任资产版本。",
                "一致性快照包含全部 pinning 规则，导出前请确认接收方；日志不采集网络请求或密钥。",
                "SQLITE_OPEN_READONLY 保证不修改规则；WAL 模式读取仍可能参与 SQLite 共享内存协调。"
            ]
        )
    }

    public static func inspect(
        path: String = protectedDatabasePath,
        sessionID: UUID,
        requireRoot: Bool = true,
        maximumSnapshotBytes: Int = 16 * 1024 * 1024,
        log: (String) -> Void
    ) -> DiagnosticEnvelope {
        var report = initialReport(sessionID: sessionID, path: path)
        log("诊断开始 session=\(sessionID)，uid=\(getuid())，euid=\(geteuid())，system_build=\(report.device.systemBuild)")
        report.checks.append(DiagnosticCheck(
            name: "root_identity",
            level: geteuid() == 0 ? .pass : (requireRoot ? .fail : .warning),
            detail: geteuid() == 0 ? "effective UID = 0" : "effective UID = \(geteuid())；未证明 root 权限"
        ))
        if requireRoot && geteuid() != 0 {
            report.finishedAt = Date()
            log("ERROR root 验证失败；未读取受保护数据库")
            return DiagnosticEnvelope(report: report, snapshot: nil)
        }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            report.database.fileSize = (attributes[.size] as? NSNumber)?.int64Value
            report.database.ownerID = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
            report.database.groupID = (attributes[.groupOwnerAccountID] as? NSNumber)?.uint32Value
            report.database.fileID = (attributes[.systemFileNumber] as? NSNumber)?.uint64Value
            report.database.deviceID = (attributes[.systemNumber] as? NSNumber)?.uint64Value
            if let permissions = attributes[.posixPermissions] as? NSNumber {
                report.database.posixPermissions = String(format: "%04o", permissions.uint32Value)
            }
            report.checks.append(DiagnosticCheck(name: "source_metadata", level: .pass, detail: "已读取源文件属性"))
            let capture = try SQLitePinningReader(maximumSnapshotBytes: maximumSnapshotBytes)
                .capture(path: path, hosts: targetHosts, log: log)
            report.database.schemaVersion = capture.schemaVersion
            report.database.contentVersion = capture.contentVersion
            report.database.ruleCount = capture.ruleCount
            report.database.journalMode = capture.journalMode
            report.database.snapshotByteCount = capture.snapshot.count
            report.database.snapshotSHA256 = SHA256.hash(data: capture.snapshot)
                .map { String(format: "%02x", $0) }.joined()
            report.hostMatches = capture.matches
            report.checks.append(DiagnosticCheck(
                name: "read_only_snapshot", level: .pass,
                detail: "只读源连接、backup API、快照 quick_check 均通过"
            ))
            for match in capture.matches {
                report.checks.append(DiagnosticCheck(
                    name: "hostname:\(match.hostname)",
                    level: match.rules.isEmpty ? .warning : .pass,
                    detail: "匹配 \(match.rules.count) 条 hostname 规则；不代表已观测实际 TLS 校验"
                ))
                log("域名 \(match.hostname)：\(match.rules.count) 条规则")
            }
            report.status = capture.matches.contains { $0.rules.isEmpty } ? .partial : .complete
            report.finishedAt = Date()
            log("诊断结束 status=\(report.status.rawValue)，写权限仍未测试")
            return DiagnosticEnvelope(report: report, snapshot: capture.snapshot)
        } catch {
            report.checks.append(DiagnosticCheck(
                name: "database_read", level: .fail, detail: error.localizedDescription
            ))
            report.finishedAt = Date()
            log("ERROR \(error.localizedDescription)")
            return DiagnosticEnvelope(report: report, snapshot: nil)
        }
    }

    private static func systemValue(_ name: String) -> String {
        var count = 0
        guard sysctlbyname(name, nil, &count, nil, 0) == 0, count > 0 else {
            return "unavailable (errno \(errno))"
        }
        var bytes = [CChar](repeating: 0, count: count)
        guard sysctlbyname(name, &bytes, &count, nil, 0) == 0 else {
            return "unavailable (errno \(errno))"
        }
        return String(cString: bytes)
    }
}
