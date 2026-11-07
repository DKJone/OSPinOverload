import CryptoKit
import Darwin
import Foundation

@_silgen_name("posix_spawnattr_set_persona_np")
private func setPersona(_ attributes: UnsafePointer<posix_spawnattr_t?>, _ persona: uid_t, _ flags: UInt32) -> Int32
@_silgen_name("posix_spawnattr_set_persona_uid_np")
private func setPersonaUID(_ attributes: UnsafePointer<posix_spawnattr_t?>, _ uid: uid_t) -> Int32
@_silgen_name("posix_spawnattr_set_persona_gid_np")
private func setPersonaGID(_ attributes: UnsafePointer<posix_spawnattr_t?>, _ gid: gid_t) -> Int32

struct RootRunnerError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

private final class PipeCapture {
    private let handle: FileHandle
    private let logger: FileLogger?
    private let limit: Int
    private let lock = NSLock()
    private var data = Data()
    private var failure: Error?

    init(fd: Int32, limit: Int, logger: FileLogger? = nil) {
        handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        self.limit = limit
        self.logger = logger
    }

    func drain() {
        do {
            while let chunk = try handle.read(upToCount: 16_384), !chunk.isEmpty {
                lock.lock()
                if data.count + chunk.count <= limit {
                    data.append(chunk)
                    do { try logger?.appendBytes(chunk) } catch { failure = error }
                } else {
                    failure = RootRunnerError(message: "helper 输出超过大小限制")
                }
                lock.unlock()
            }
        } catch {
            lock.lock()
            failure = error
            lock.unlock()
        }
    }

    func result() throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        if let failure { throw failure }
        return data
    }
}

final class RootDiagnosticRunner {
    private let store: SessionStore
    private let queue = DispatchQueue(label: "com.dkjone.OSPinOverload.diagnostics", qos: .utility)

    init(store: SessionStore) { self.store = store }

    func run(
        session: DiagnosticSession,
        operation: DiagnosticOperation = .diagnose,
        progress: ((String) -> Void)? = nil,
        completion: @escaping (Result<DiagnosticReport, Error>) -> Void
    ) {
        let update: (String) -> Void = { text in DispatchQueue.main.async { progress?(text) } }
        queue.async {
            var logger: FileLogger?
            do {
                let sessionLogger = try FileLogger(url: session.appLogURL)
                logger = sessionLogger
                if operation == .permissions {
                    let report = try self.compareAccess(session: session, logger: sessionLogger)
                    DispatchQueue.main.async { completion(.success(report)) }
                    return
                }
                if operation == .restore {
                    update("正在核对备份并恢复…")
                    let reference = try self.store.recoveryReference(session: session)
                    let restored = try self.execute(session: session, logger: sessionLogger, changeReference: reference, changeAction: .restore)
                    try self.store.save(restored, to: session)
                    if restored.report.status == .complete && restored.report.change?.verified == true {
                        try self.store.finishRestore()
                    }
                    try sessionLogger.append("报告已持久化 status=\(restored.report.status.rawValue)；仅验证数据库状态，不证明 TLS/定位")
                    DispatchQueue.main.async { completion(.success(restored.report)) }
                    return
                }
                if operation == .apply { try self.store.ensureNoPendingChange() }
                update("正在检查兼容性…")
                var envelope = try self.execute(session: session, logger: sessionLogger)
                try self.saveStage(envelope, session: session, operation: operation)
                if operation == .prepare || operation == .apply {
                    guard envelope.report.status == .complete else {
                        var report = envelope.report
                        report.operation = operation
                        report.status = .failed
                        report.checks.append(DiagnosticCheck(name: "preparation_baseline", level: .fail, detail: "只读诊断未完成，未生成基线、未开始读写预检"))
                        envelope = DiagnosticEnvelope(report: report, snapshot: envelope.snapshot)
                        try self.store.save(envelope, to: session)
                        try sessionLogger.append("ERROR 准备停止：只读诊断未完成；未启动预检 helper")
                        try sessionLogger.append("报告已持久化 status=failed")
                        DispatchQueue.main.async { completion(.success(report)) }
                        return
                    }
                    try sessionLogger.append("准备阶段：先保存独立恢复基线，再生成副本候选并演练规则恢复")
                    update("正在保存备份并演练恢复…")
                    let plan = try self.store.prepareBaselineAndPlan(envelope, session: session)
                    try sessionLogger.append("基线已同步落盘并校验；offline_plan rules=\(plan.originalRuleCount)->\(plan.candidateRuleCount) restore_verified=\(plan.logicalRestoreVerified)")
                    let metadataHash = PinningPreparation.sha256(try DiagnosticEncoding.encoder().encode(envelope.report.database))
                    update("正在验证修改条件…")
                    envelope = try self.execute(session: session, logger: sessionLogger,
                                                baselineSHA256: plan.baselineSHA256, baselineMetadataSHA256: metadataHash)
                    var report = envelope.report
                    report.preparation?.offlinePlan = plan
                    report.checks.append(DiagnosticCheck(
                        name: "recovery_baseline", level: .pass,
                        detail: "基线独立保存在 \(self.store.baselineDirectory.appendingPathComponent(session.id.uuidString).path)，不随 Latest 覆盖"
                    ))
                    report.checks.append(DiagnosticCheck(name: "offline_plan", level: .pass, detail: "副本只移除 1 条定位 hostname 规则；原始 BLOB 规则恢复后所有规则/admin/schema 等价"))
                    envelope = DiagnosticEnvelope(report: report, snapshot: envelope.snapshot)
                    try self.saveStage(envelope, session: session, operation: operation)
                    if operation == .apply {
                        guard report.status == .complete else { throw RootRunnerError(message: "新基线与回滚预检未通过，不应用规则") }
                        let reference = try self.store.beginChange(session: session)
                        update("正在调整规则并核对结果…")
                        envelope = try self.execute(session: session, logger: sessionLogger, changeReference: reference, changeAction: .apply)
                        var changedReport = envelope.report
                        changedReport.preparation = report.preparation
                        envelope = DiagnosticEnvelope(report: changedReport, snapshot: envelope.snapshot)
                        try self.store.save(envelope, to: session)
                    }
                }
                try sessionLogger.append("报告已持久化 status=\(envelope.report.status.rawValue)")
                DispatchQueue.main.async { completion(.success(envelope.report)) }
            } catch {
                do {
                    try logger?.append("ERROR \(error.localizedDescription)")
                    if operation == .apply || operation == .restore {
                        try logger?.append("ERROR 变更未获完整确认；可能已提交，保留恢复引用。请导出 change-progress.json，勿重复应用或覆盖数据库。")
                    }
                    try self.store.applicationLogger.append("ERROR session=\(session.id) \(error.localizedDescription)")
                    if FileManager.default.fileExists(atPath: session.reportURL.path) {
                        var report = try DiagnosticEncoding.decoder().decode(DiagnosticReport.self, from: Data(contentsOf: session.reportURL))
                        report.operation = operation
                        report.status = .failed
                        report.finishedAt = Date()
                        if operation == .apply || operation == .restore {
                            let progress = session.directory.appendingPathComponent(ControlledRuleChange.progressFileName)
                            if FileManager.default.fileExists(atPath: progress.path) {
                                report.change = try DiagnosticEncoding.decoder().decode(RuleChangeResult.self, from: Data(contentsOf: progress))
                            }
                            report.database.writeAccess = report.change?.commitState == .committed ? "commit_succeeded" : "commit_unknown"
                        }
                        report.checks.append(DiagnosticCheck(name: "controller_operation", level: .fail, detail: error.localizedDescription))
                        try self.store.save(DiagnosticEnvelope(report: report, snapshot: nil), to: session)
                    }
                    try Data("诊断执行失败：\(error.localizedDescription)\n请同时导出 app.log 和 worker.log。\n".utf8)
                        .write(to: session.summaryURL, options: .atomic)
                } catch let persistenceError {
                    let combined = RootRunnerError(
                        message: "诊断失败：\(error.localizedDescription)\n日志保存也失败：\(persistenceError.localizedDescription)"
                    )
                    DispatchQueue.main.async { completion(.failure(combined)) }
                    return
                }
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }

    private func saveStage(_ envelope: DiagnosticEnvelope, session: DiagnosticSession, operation: DiagnosticOperation) throws {
        var report = envelope.report
        if operation == .apply {
            report.operation = .apply
            if report.status == .complete { report.status = .partial }
            report.checks.append(DiagnosticCheck(name: "change_pending", level: .warning, detail: "准备阶段已保存，尚未取得应用提交结果；检查变更阶段证据"))
        }
        try store.save(DiagnosticEnvelope(report: report, snapshot: envelope.snapshot), to: session)
    }

    private func compareAccess(session: DiagnosticSession, logger: FileLogger) throws -> DiagnosticReport {
        var report = DiagnosticEngine.initialReport(sessionID: session.id, operation: .permissions)
        report.accessProbes = []
        report.accessFailures = []
        for profile in FileAccessProfile.allCases {
            do {
                let envelope = try execute(session: session, logger: logger, accessProfile: profile)
                report.accessProbes?.append(contentsOf: envelope.report.accessProbes ?? [])
                report.checks.append(contentsOf: envelope.report.checks.map {
                    DiagnosticCheck(name: "\(profile.rawValue):\($0.name)", level: $0.level, detail: $0.detail)
                })
            } catch {
                report.accessFailures?.append(FileAccessFailure(profile: profile, detail: error.localizedDescription))
                report.checks.append(DiagnosticCheck(name: "\(profile.rawValue):worker", level: .fail, detail: error.localizedDescription))
                try logger.append("ERROR profile=\(profile.rawValue) \(error.localizedDescription)；保留已有结果并继续另一个身份")
            }
            report.status = FileAccessDiagnostics.comparisonStatus(probes: report.accessProbes ?? [], failures: report.accessFailures ?? [])
            report.finishedAt = Date()
            try store.save(DiagnosticEnvelope(report: report, snapshot: nil), to: session)
            try logger.append("权限对照阶段已持久化 profile=\(profile.rawValue) status=\(report.status.rawValue)")
        }
        try logger.append("报告已持久化 status=\(report.status.rawValue)；仅完成权限信息采集，不代表可提交写入")
        return report
    }

    private func execute(session: DiagnosticSession, logger: FileLogger,
                         baselineSHA256: String? = nil, baselineMetadataSHA256: String? = nil,
                         accessProfile: FileAccessProfile? = nil,
                         changeReference: RuleRecoveryReference? = nil, changeAction: DiagnosticOperation? = nil) throws -> DiagnosticEnvelope {
        guard let executable = Bundle.main.executablePath else {
            throw RootRunnerError(message: "找不到当前应用可执行文件")
        }
        var outputFDs: [Int32] = [-1, -1]
        var errorFDs: [Int32] = [-1, -1]
        guard pipe(&outputFDs) == 0 else { throw posixError("stdout pipe", errno) }
        guard pipe(&errorFDs) == 0 else {
            outputFDs.forEach { close($0) }
            throw posixError("stderr pipe", errno)
        }
        var readDescriptorsTransferred = false
        defer {
            close(outputFDs[1])
            close(errorFDs[1])
            if !readDescriptorsTransferred {
                close(outputFDs[0])
                close(errorFDs[0])
            }
        }
        var actions: posix_spawn_file_actions_t?
        try check(posix_spawn_file_actions_init(&actions), "file actions init")
        defer { posix_spawn_file_actions_destroy(&actions) }
        try check(posix_spawn_file_actions_adddup2(&actions, outputFDs[1], STDOUT_FILENO), "stdout dup2")
        try check(posix_spawn_file_actions_adddup2(&actions, errorFDs[1], STDERR_FILENO), "stderr dup2")
        for fd in outputFDs + errorFDs {
            try check(posix_spawn_file_actions_addclose(&actions, fd), "close child pipe")
        }
        var attributes: posix_spawnattr_t?
        try check(posix_spawnattr_init(&attributes), "spawn attributes init")
        defer { posix_spawnattr_destroy(&attributes) }
        #if !targetEnvironment(simulator)
        let requestedID = accessProfile?.id ?? 0
        try logger.append("persona 配置 persona=99 flags=1 uid=\(requestedID) gid=\(requestedID)；caller_uid=\(getuid()) caller_euid=\(geteuid())")
        try check(setPersona(&attributes, 99, 1), "persona override", logger: logger)
        try check(setPersonaUID(&attributes, requestedID), "persona uid", logger: logger)
        try check(setPersonaGID(&attributes, requestedID), "persona gid", logger: logger)
        #endif

        let strings: [String]
        if let changeReference, let changeAction {
            guard [.apply, .restore].contains(changeAction), baselineSHA256 == nil,
                  baselineMetadataSHA256 == nil, accessProfile == nil else { throw RootRunnerError(message: "非法变更参数组合") }
            strings = [executable, "--\(changeAction.rawValue)", session.id.uuidString, changeReference.baselineID.uuidString, changeReference.receiptSHA256]
        } else if let accessProfile {
            guard baselineSHA256 == nil, baselineMetadataSHA256 == nil else { throw RootRunnerError(message: "权限模式不能携带预检基线") }
            strings = [executable, "--permissions", session.id.uuidString, accessProfile.rawValue]
        } else if let baselineSHA256, let baselineMetadataSHA256 {
            strings = [executable, "--prepare", session.id.uuidString, baselineSHA256, baselineMetadataSHA256]
        } else {
            guard baselineSHA256 == nil, baselineMetadataSHA256 == nil else { throw RootRunnerError(message: "预检缺少基线身份摘要") }
            strings = [executable, "--diagnose", session.id.uuidString]
        }
        #if targetEnvironment(simulator)
        let simulator = true
        #else
        let simulator = false
        #endif
        let inheritedEnvironment = ProcessInfo.processInfo.environment
        let environmentStrings = WorkerEnvironment.make(current: inheritedEnvironment, simulator: simulator)
        let runtimeKeys = ["HOME", "TMPDIR", "CFFIXED_USER_HOME"].filter { inheritedEnvironment[$0] != nil }
        try logger.append("保留进程运行环境；存在的路径键=\(runtimeKeys.joined(separator: ","))；不记录值")
        var argv: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) } + [nil]
        var environment: [UnsafeMutablePointer<CChar>?] = environmentStrings.map { strdup($0) } + [nil]
        defer {
            argv.compactMap { $0 }.forEach { free($0) }
            environment.compactMap { $0 }.forEach { free($0) }
        }
        guard argv.dropLast().allSatisfy({ $0 != nil }),
              environment.dropLast().allSatisfy({ $0 != nil }) else {
            throw RootRunnerError(message: "分配 helper 参数失败")
        }
        var pid: pid_t = 0
        let workerLogger = try FileLogger(url: session.workerLogURL)
        let expectedOperation: DiagnosticOperation = changeAction ?? (accessProfile != nil ? .permissions : (baselineSHA256 == nil ? .diagnose : .prepare))
        let timeout: UInt64 = changeAction == nil ? 30 : 150
        try logger.append("启动同二进制 helper；mode=\(expectedOperation.rawValue) profile=\(accessProfile?.rawValue ?? "root") 固定数据库；父进程超时 \(timeout) 秒")
        let code = posix_spawn(&pid, executable, &actions, &attributes, &argv, &environment)
        try check(code, "posix_spawn")
        close(outputFDs[1])
        close(errorFDs[1])
        outputFDs[1] = -1
        errorFDs[1] = -1
        var childReaped = false
        defer {
            if !childReaped {
                var cleanupStatus: Int32 = 0
                if waitpid(pid, &cleanupStatus, WNOHANG) == 0 {
                    kill(pid, SIGKILL)
                    while waitpid(pid, &cleanupStatus, 0) < 0 && errno == EINTR {}
                }
            }
        }

        let stdout = PipeCapture(fd: outputFDs[0], limit: 32 * 1024 * 1024)
        let stderr = PipeCapture(
            fd: errorFDs[0], limit: 1024 * 1024, logger: workerLogger
        )
        readDescriptorsTransferred = true
        let group = DispatchGroup()
        for capture in [stdout, stderr] {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                capture.drain()
                group.leave()
            }
        }
        try logger.append("posix_spawn return=0 pid=\(pid)")
        var status: Int32 = 0
        let deadline = DispatchTime.now().uptimeNanoseconds + timeout * 1_000_000_000
        var timedOut = false
        while true {
            let result = waitpid(pid, &status, WNOHANG)
            if result == pid {
                childReaped = true
                break
            }
            if result < 0 {
                if errno == EINTR { continue }
                if errno == ECHILD { childReaped = true }
                throw posixError("waitpid", errno)
            }
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                timedOut = true
                kill(pid, SIGTERM)
                Thread.sleep(forTimeInterval: 0.2)
                if waitpid(pid, &status, WNOHANG) == 0 {
                    kill(pid, SIGKILL)
                    while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
                }
                childReaped = true
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        guard group.wait(timeout: .now() + 3) == .success else {
            throw RootRunnerError(message: "helper 输出管道未关闭")
        }
        try logger.append("helper pid=\(pid) wait_status=\(status) timed_out=\(timedOut)")
        _ = try stderr.result()
        if timedOut { throw RootRunnerError(message: "root helper 超时；变更结果可能未知，保留恢复引用，不能保证 mobile 的终止信号获准") }
        let output = try stdout.result()
        guard status & 0x7f == 0 else {
            throw RootRunnerError(message: "root helper 异常终止，signal=\(status & 0x7f)")
        }
        let exitCode = (status >> 8) & 0xff
        let envelope: DiagnosticEnvelope
        do {
            envelope = try DiagnosticEncoding.decoder().decode(DiagnosticEnvelope.self, from: output)
        } catch {
            throw RootRunnerError(message: "helper 返回格式无效，exit=\(exitCode)：\(error.localizedDescription)")
        }
        guard envelope.report.sessionID == session.id,
              envelope.report.identity.pid == pid,
              envelope.report.reportFormatVersion == 1,
              envelope.report.appVersion == DiagnosticAppVersion.current,
              envelope.report.appBuild == DiagnosticAppVersion.build,
              envelope.report.operation == expectedOperation,
              envelope.report.database.sourcePath == DiagnosticEngine.protectedDatabasePath else {
            throw RootRunnerError(message: "helper 报告标识或来源校验失败")
        }
        if let baselineSHA256 {
            guard let preparation = envelope.report.preparation,
                  preparation.baselineSHA256 == baselineSHA256, !preparation.actualWriteCommitted,
                  preparation.baselineMetadataSHA256 == baselineMetadataSHA256,
                  preparation.offlinePlan == nil,
                  envelope.report.status == .failed ||
                    (preparation.readWriteOpened == true && preparation.transactionBegan == true &&
                     preparation.rollbackSucceeded == true && preparation.sourceUnchanged == true) else {
                throw RootRunnerError(message: "helper 预检协议或基线校验失败")
            }
        } else if envelope.report.preparation != nil {
            throw RootRunnerError(message: "只读 helper 返回了非预期预检结果")
        }
        guard (exitCode == 0 && envelope.report.status != .failed) ||
                (exitCode == 2 && envelope.report.status == .failed) else {
            throw RootRunnerError(message: "helper 退出状态和报告状态不一致，exit=\(exitCode)")
        }
        if let accessProfile {
            guard FileAccessDiagnostics.validWorkerResult(envelope, profile: accessProfile) else {
                throw RootRunnerError(message: "权限 helper 身份、范围或结果结构校验失败")
            }
            return envelope
        }
        if let changeReference, let changeAction {
            guard let change = envelope.report.change, change.baselineID == changeReference.baselineID,
                  change.baselineReceiptSHA256 == changeReference.receiptSHA256, change.action == changeAction,
                  envelope.report.status == .failed ||
                    (change.verified && (change.commitState == .committed || (changeAction == .restore && change.alreadyRestored))) else {
                throw RootRunnerError(message: "变更 helper 返回无效或未知提交结果；保留恢复引用")
            }
        } else if envelope.report.change != nil { throw RootRunnerError(message: "非变更 helper 返回提交结果") }
        guard envelope.report.accessProbes == nil, envelope.report.accessFailures == nil else {
            throw RootRunnerError(message: "原有诊断模式返回了非预期权限结果")
        }
        if envelope.report.status != .failed && envelope.report.identity.effectiveUID != 0 {
            throw RootRunnerError(message: "报告没有证明 root 身份")
        }
        if let snapshot = envelope.snapshot {
            let hash = SHA256.hash(data: snapshot).map { String(format: "%02x", $0) }.joined()
            guard snapshot.count <= 16 * 1024 * 1024,
                  snapshot.count == envelope.report.database.snapshotByteCount,
                  hash == envelope.report.database.snapshotSHA256 else {
                throw RootRunnerError(message: "helper 快照大小或 SHA256 校验失败")
            }
        } else if envelope.report.status != .failed {
            throw RootRunnerError(message: "helper 声称诊断完成但没有提供快照")
        }
        return envelope
    }

    private func check(_ code: Int32, _ operation: String, logger: FileLogger? = nil) throws {
        try logger?.append("\(operation) return=\(code)")
        if code != 0 { throw posixError(operation, code) }
    }

    private func posixError(_ operation: String, _ code: Int32) -> RootRunnerError {
        RootRunnerError(message: "\(operation) 失败：\(code) \(String(cString: strerror(code)))")
    }
}
