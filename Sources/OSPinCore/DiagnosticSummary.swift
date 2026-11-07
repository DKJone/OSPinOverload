import Foundation

public enum DiagnosticSummary {
    public static func text(_ report: DiagnosticReport) -> String {
        if report.operation == .permissions { return accessText(report) }
        if report.operation == .apply || report.operation == .restore {
            let change = report.change
            return ([
                "OSPinOverload \(report.appVersion) build \(report.appBuild ?? "unknown") — \(report.operation == .apply ? "应用单条规则变更" : "恢复原始规则")",
                "Session: \(report.sessionID)",
                "状态: \(report.status.rawValue)",
                "恢复基线: \(change?.baselineID.uuidString ?? "尚未建立")",
                "COMMIT 状态: \(change?.commitState.rawValue ?? "未启动变更 helper；检查阶段日志")",
                "独立完整逻辑读回: \(change?.verified == true)",
                "已是原始状态（未写入）: \(change?.alreadyRestored == true)",
                "规则数: \(change?.beforeRuleCount.map(String.init) ?? "未知") -> \(change?.afterRuleCount.map(String.init) ?? "未知")",
                "源快照: \(report.database.snapshotSHA256 ?? "未取得")",
                change?.detail ?? "未证明已提交；如 helper 中断须检查 change-progress.json 与恢复引用",
                "不自动重载 trustd/locationd，不阻止更新；规则变更/恢复成功不等于 TLS 或定位通过。"
            ] + report.checks.map { "[\($0.level.rawValue)] \($0.name): \($0.detail)" }).joined(separator: "\n")
        }
        let database = report.database
        var lines = [
            "OSPinOverload \(report.appVersion) — \(report.operation == .prepare ? "变更前准备" : "只读诊断")",
            "应用 Build: \(report.appBuild ?? "旧版未记录")",
            "Session: \(report.sessionID)",
            "状态: \(report.status.rawValue)",
            "设备: \(report.device.machine)",
            "系统: \(report.device.systemVersion)",
            "系统 Build: \(report.device.systemBuild)",
            "UID/EUID: \(report.identity.uid)/\(report.identity.effectiveUID)",
            "GID/EGID: \(report.identity.gid)/\(report.identity.effectiveGID)",
            "源数据库: \(database.sourcePath)",
            "权限: \(database.posixPermissions ?? "未取得")",
            "源属主/属组: \(database.ownerID.map(String.init) ?? "未取得")/\(database.groupID.map(String.init) ?? "未取得")",
            "Schema: \(database.schemaVersion.map(String.init) ?? "未取得")",
            "Content: \(database.contentVersion.map(String.init) ?? "未取得")",
            "规则总数: \(database.ruleCount.map(String.init) ?? "未取得")",
            "Journal: \(database.journalMode ?? "未取得")",
            "快照 SHA256: \(database.snapshotSHA256 ?? "未生成")",
            "实际写入提交: 未测试（本版不修改系统规则）",
            "",
            "检查结果"
        ]
        if let preparation = report.preparation {
            lines += [
                "恢复基线 SHA256: \(preparation.baselineSHA256)",
                "读写连接: \(preparation.readWriteOpened.map(String.init) ?? "未开始")",
                "BEGIN IMMEDIATE: \(preparation.transactionBegan.map(String.init) ?? "未开始")",
                "ROLLBACK: \(preparation.rollbackSucceeded.map(String.init) ?? "未开始")",
                "预检前后源快照一致: \(preparation.sourceUnchanged.map(String.init) ?? "未验证")"
            ]
            if let plan = preparation.offlinePlan {
                lines += [
                    "离线候选规则数: \(plan.originalRuleCount) -> \(plan.candidateRuleCount)",
                    "目标规则指纹: \(plan.targetRuleFingerprint)",
                    "离线恢复等价: \(plan.logicalRestoreVerified)",
                    plan.warning
                ]
            }
        }
        for check in report.checks {
            lines.append("[\(check.level.rawValue)] \(check.name): \(check.detail)")
        }
        for match in report.hostMatches {
            lines.append("\n域名: \(match.hostname)，匹配 \(match.rules.count) 条规则")
            for rule in match.rules {
                lines.append("Policy: \(rule.policyName)")
                lines.append("Suffix / Regex: \(rule.domainSuffix) / \(rule.labelRegex)")
                lines.append("TransparentConnection: \(rule.transparentConnection.map(String.init) ?? "NULL")")
                lines.append("规则指纹: \(rule.sourceFingerprint ?? "旧版未记录")")
                lines.append(rule.policiesJSON)
            }
        }
        lines.append("\n诊断边界")
        lines.append(contentsOf: report.limitations)
        return lines.joined(separator: "\n")
    }

    private static func accessText(_ report: DiagnosticReport) -> String {
        var lines = [
            "OSPinOverload \(report.appVersion) build \(report.appBuild ?? "unknown") — 权限对照诊断",
            "Session: \(report.sessionID)",
            "采集状态: \(report.status.rawValue)（不是写权限结论）",
            "设备/系统: \(report.device.machine) / \(report.device.systemVersion) / \(report.device.systemBuild)",
            "报告汇总进程 UID/EUID: \(report.identity.uid)/\(report.identity.effectiveUID)",
            "源路径: \(report.database.sourcePath)",
            "文件内容读取/写入: 均未执行；未调用 SQLite，未提交修改"
        ]
        for probe in report.accessProbes ?? [] {
            lines += [
                "",
                "=== \(probe.profile.rawValue) 请求 UID/GID \(probe.profile.id) ===",
                "实际 UID/EUID: \(probe.identity.uid)/\(probe.identity.effectiveUID)",
                "实际 GID/EGID: \(probe.identity.gid)/\(probe.identity.effectiveGID)",
                "身份匹配: \(probe.identityVerified)；采集状态: \(probe.status.rawValue)"
            ]
            if let entitlement = probe.runtimeEntitlement {
                lines += [
                    "运行时 entitlement: \(entitlement.key)",
                    "查询: \(entitlement.method) pid=\(entitlement.processID) state=\(entitlement.state.rawValue) value=\(entitlement.value.map(String.init) ?? "未知/无 Boolean")",
                    "csops 长度查询 return/errno=\(entitlement.probeReturnValue.map(String.init) ?? "未调用")/\(entitlement.probeErrno.map(String.init) ?? "未调用")",
                    "csops 读取 return/errno=\(entitlement.readReturnValue.map(String.init) ?? "未调用")/\(entitlement.readErrno.map(String.init) ?? "未调用")",
                    entitlement.detail
                ]
            } else {
                lines.append("运行时 entitlement: 旧报告未采集，不猜测")
            }
            for path in probe.paths {
                lines.append("路径: \(path.path)")
                lines.append("lstat errno=\(path.statErrno) \(FileAccessDiagnostics.errorText(path.statErrno))")
                if let attributes = path.attributes {
                    lines += [
                        "mode=\(String(format: "%06o", attributes.mode)) uid/gid=\(attributes.ownerID)/\(attributes.groupID) size=\(attributes.size)",
                        "device/inode=\(attributes.deviceID)/\(attributes.fileID)",
                        "flags=\(String(format: "0x%08x", attributes.flags)) \(attributes.flagNames.joined(separator: ","))"
                    ]
                }
                if let code = path.statfsErrno {
                    lines.append("statfs errno=\(code) \(FileAccessDiagnostics.errorText(code))")
                } else {
                    lines.append("statfs 未调用: \(path.statfsSkippedReason ?? "原因未记录")")
                }
                if let mount = path.mount {
                    lines.append("mount=\(mount.mountPoint) fs=\(mount.filesystem) flags=\(String(format: "0x%08x", mount.flags)) readonly=\(mount.readOnly)")
                }
            }
            if let opened = probe.open {
                lines += [
                    "open flags=\(String(format: "0x%08x", opened.requestedFlags)) return=\(opened.returnValue) errno=\(opened.openErrno) \(FileAccessDiagnostics.errorText(opened.openErrno))",
                    "O_RDWR 描述符已确认: \(opened.readWriteDescriptorConfirmed)",
                    "F_GETFL=\(opened.getFlagsReturnValue.map(String.init) ?? "未调用") errno=\(opened.getFlagsErrno.map(String.init) ?? "未调用")",
                    "fstat errno=\(opened.descriptorStatErrno.map(String.init) ?? "未调用") 与源匹配=\(opened.descriptorMatchesSource.map(String.init) ?? "未验证")",
                    "close=\(opened.closeReturnValue.map(String.init) ?? "未调用") errno=\(opened.closeErrno.map(String.init) ?? "未调用")",
                    "复查 lstat errno=\(probe.afterStatErrno.map(String.init) ?? "未调用") 元数据未变=\(probe.sourceMetadataUnchanged.map(String.init) ?? "未验证")"
                ]
            }
            if let reason = probe.skippedReason { lines.append("跳过打开: \(reason)") }
        }
        for failure in report.accessFailures ?? [] {
            lines.append("ERROR \(failure.profile.rawValue) helper: \(failure.detail)")
        }
        lines.append("\n检查结果")
        lines += report.checks.map { "[\($0.level.rawValue)] \($0.name): \($0.detail)" }
        lines.append("\n诊断边界")
        lines += report.limitations
        return lines.joined(separator: "\n")
    }
}
