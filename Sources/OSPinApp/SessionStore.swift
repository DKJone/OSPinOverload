import Foundation

final class FileLogger {
    private let lock = NSLock()
    private let handle: FileHandle

    init(url: URL, truncate: Bool = false) throws {
        if !FileManager.default.fileExists(atPath: url.path) {
            guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
                throw CocoaError(.fileWriteUnknown)
            }
        }
        handle = try FileHandle(forWritingTo: url)
        if truncate { try handle.truncate(atOffset: 0) }
        try handle.seekToEnd()
    }

    func append(_ message: String) throws {
        let line = "\(ISO8601DateFormatter().string(from: Date())) [app \(DiagnosticAppVersion.logTag)] \(message)\n"
        try appendBytes(Data(line.utf8))
    }

    func appendBytes(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        try handle.write(contentsOf: data)
        try handle.synchronize()
    }

    deinit { try? handle.close() }
}

struct DiagnosticSession {
    let id: UUID
    let directory: URL

    var reportURL: URL { directory.appendingPathComponent("report.json") }
    var summaryURL: URL { directory.appendingPathComponent("summary.txt") }
    var workerLogURL: URL { directory.appendingPathComponent("worker.log") }
    var appLogURL: URL { directory.appendingPathComponent("app.log") }
    var snapshotURL: URL { directory.appendingPathComponent("pinningrules.snapshot.sqlite3") }
}

final class SessionStore {
    let rootDirectory: URL
    let exportDirectory: URL
    let baselineDirectory: URL
    let applicationLogger: FileLogger
    private let legacyDirectory: URL
    private let latestSessionKey = "OSPinOverload.latestSession.v1"

    init() throws {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw CocoaError(.fileNoSuchFile)
        }
        legacyDirectory = documents.appendingPathComponent("OSPinOverload", isDirectory: true)
        #if targetEnvironment(simulator)
        let mediaDirectory = legacyDirectory
        #else
        let mediaDirectory = URL(fileURLWithPath: "/var/mobile/Media/OSPinOverload", isDirectory: true)
        #endif
        rootDirectory = mediaDirectory.appendingPathComponent("Diagnostics", isDirectory: true)
        exportDirectory = mediaDirectory.appendingPathComponent("Exports", isDirectory: true)
        baselineDirectory = mediaDirectory.appendingPathComponent("Baselines", isDirectory: true)
        try FileManager.default.createDirectory(
            at: rootDirectory.appendingPathComponent("Sessions", isDirectory: true),
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
        )
        applicationLogger = try FileLogger(url: rootDirectory.appendingPathComponent("app.log"), truncate: true)
        try applicationLogger.append(
            "启动 version=\(DiagnosticAppVersion.current) uid=\(getuid()) euid=\(geteuid()) system=\(ProcessInfo.processInfo.operatingSystemVersionString)"
        )
        try applicationLogger.append("本机证据保留；系统分享仅提供白名单脱敏反馈 ZIP，不附带数据库")
    }

    func createSession(operation: DiagnosticOperation = .diagnose) throws -> DiagnosticSession {
        let id = UUID()
        let directory = rootDirectory.appendingPathComponent("Sessions/\(id.uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let session = DiagnosticSession(id: id, directory: directory)
        let metadata = try DiagnosticEncoding.encoder(pretty: true).encode(DiagnosticSessionMetadata(sessionID: id, operation: operation))
        try metadata.write(to: directory.appendingPathComponent("session.json"), options: .atomic)
        try metadata.write(to: rootDirectory.appendingPathComponent("current-session.json"), options: .atomic)
        let logger = try FileLogger(url: session.appLogURL)
        try logger.append("创建 session=\(id) operation=\(operation.rawValue)；仅用户触发时启动 root helper")
        UserDefaults.standard.set(id.uuidString, forKey: latestSessionKey)
        try applicationLogger.append("session=\(id) path=\(directory.path)")
        return session
    }

    func latestSession() throws -> DiagnosticSession? {
        let currentURL = rootDirectory.appendingPathComponent("current-session.json")
        let value: String?
        if let stored = UserDefaults.standard.string(forKey: latestSessionKey) {
            value = stored
        } else if FileManager.default.fileExists(atPath: currentURL.path) {
            value = try DiagnosticEncoding.decoder().decode(
                DiagnosticSessionMetadata.self, from: boundedData(currentURL, limit: 4096)
            ).sessionID.uuidString
        } else { value = nil }
        guard let value else { return nil }
        guard let id = UUID(uuidString: value) else { throw PinningPreparation.failure("上次记录标识无效") }
        let directory = rootDirectory.appendingPathComponent("Sessions/\(id.uuidString)", isDirectory: true)
        if FileManager.default.fileExists(atPath: directory.path) {
            return DiagnosticSession(id: id, directory: directory)
        }
        let oldDirectory = legacyDirectory.appendingPathComponent("Sessions/\(id.uuidString)", isDirectory: true)
        guard FileManager.default.fileExists(atPath: oldDirectory.path) else { return nil }
        return DiagnosticSession(id: id, directory: oldDirectory)
    }

    func export(_ session: DiagnosticSession) throws -> DiagnosticExport {
        guard try isCurrentBuild(session) else {
            throw NSError(domain: "OSPinOverload.Export", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "上次诊断来自其他 build，请先重新运行诊断再导出。"
            ])
        }
        let logger = try FileLogger(url: session.appLogURL)
        try logger.append("开始 USB 文件导出；不调用 ShareSheet/AirDrop")
        try applicationLogger.append("开始导出 session=\(session.id)")
        let result = try DiagnosticExporter.export(
            sessionID: session.id, sourceDirectory: session.directory,
            exportRoot: exportDirectory, applicationLog: rootDirectory.appendingPathComponent("app.log")
        )
        try logger.append("导出完成 path=\(result.directory.path) files=\(result.receipt.files.count)")
        try applicationLogger.append("导出完成 session=\(session.id)")
        return result
    }

    func isCurrentBuild(_ session: DiagnosticSession) throws -> Bool {
        let url = session.directory.appendingPathComponent("session.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return false }
        let metadata = try DiagnosticEncoding.decoder().decode(
            DiagnosticSessionMetadata.self, from: Data(contentsOf: url)
        )
        return metadata.sessionID == session.id &&
            metadata.appVersion == DiagnosticAppVersion.current && metadata.appBuild == DiagnosticAppVersion.build
    }

    func save(_ envelope: DiagnosticEnvelope, to session: DiagnosticSession) throws {
        try DiagnosticEncoding.encoder(pretty: true).encode(envelope.report)
            .write(to: session.reportURL, options: .atomic)
        try Data(DiagnosticSummary.text(envelope.report).utf8).write(to: session.summaryURL, options: .atomic)
        if let snapshot = envelope.snapshot {
            try snapshot.write(to: session.snapshotURL, options: .atomic)
        }
    }

    func prepareBaselineAndPlan(_ envelope: DiagnosticEnvelope, session: DiagnosticSession) throws -> OfflinePinningPlan {
        let baseline = baselineDirectory.appendingPathComponent(session.id.uuidString, isDirectory: true)
        _ = try RecoveryBaselineStore.save(envelope, directory: baseline)
        for name in RecoveryBaselineStore.fileNames {
            try FileManager.default.copyItem(at: baseline.appendingPathComponent(name), to: session.directory.appendingPathComponent(name))
        }
        guard let snapshot = envelope.snapshot else { throw PinningPreparation.failure("基线没有快照") }
        let planDirectory = rootDirectory.appendingPathComponent("Plans/\(session.id.uuidString)", isDirectory: true)
        let plan = try PinningPreparation.createOfflinePlan(snapshot: snapshot, report: envelope.report, directory: planDirectory)
        for name in ["plan.json", "candidate.sqlite3", "restored.sqlite3"] {
            try FileManager.default.copyItem(at: planDirectory.appendingPathComponent(name), to: session.directory.appendingPathComponent(name))
        }
        try RecoveryBaselineStore.verify(directory: baseline, sessionID: session.id)
        try RecoveryBaselineStore.verify(directory: session.directory, sessionID: session.id)
        return plan
    }

    private var recoveryURL: URL { rootDirectory.appendingPathComponent(ControlledRuleChange.referenceFileName) }

    func ensureNoPendingChange() throws {
        guard !FileManager.default.fileExists(atPath: recoveryURL.path) else {
            throw PinningPreparation.failure("已有未完成的应用/恢复引用；请先恢复，不允许覆盖旧基线")
        }
    }

    func beginChange(session: DiagnosticSession) throws -> RuleRecoveryReference {
        try ensureNoPendingChange()
        let baseline = baselineDirectory.appendingPathComponent(session.id.uuidString)
        try RecoveryBaselineStore.verify(directory: baseline, sessionID: session.id)
        let reference = RuleRecoveryReference(
            baselineID: session.id,
            receiptSHA256: PinningPreparation.sha256(try Data(contentsOf: baseline.appendingPathComponent("baseline-receipt.json")))
        )
        let data = try DiagnosticEncoding.encoder(pretty: true).encode(reference)
        try data.write(to: recoveryURL, options: .withoutOverwriting)
        let handle = try FileHandle(forWritingTo: recoveryURL)
        do {
            try handle.synchronize()
            try handle.close()
        } catch {
            try handle.close()
            throw error
        }
        guard try Data(contentsOf: recoveryURL) == data else { throw PinningPreparation.failure("恢复引用回读失败") }
        try data.write(to: session.directory.appendingPathComponent(ControlledRuleChange.referenceFileName), options: .atomic)
        return reference
    }

    func recoveryReference(session: DiagnosticSession) throws -> RuleRecoveryReference {
        guard FileManager.default.fileExists(atPath: recoveryURL.path) else {
            throw PinningPreparation.failure("没有未完成的恢复引用；不会自动选择旧基线或修改数据库")
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: recoveryURL.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? NSNumber, size.intValue <= 4096 else {
            throw PinningPreparation.failure("恢复引用不是有效小文件；不能猜测基线")
        }
        let data = try Data(contentsOf: recoveryURL)
        let reference = try DiagnosticEncoding.decoder().decode(RuleRecoveryReference.self, from: data)
        let baseline = baselineDirectory.appendingPathComponent(reference.baselineID.uuidString)
        try RecoveryBaselineStore.verify(directory: baseline, sessionID: reference.baselineID, requireCurrentBuild: false)
        guard PinningPreparation.sha256(try Data(contentsOf: baseline.appendingPathComponent("baseline-receipt.json"))) == reference.receiptSHA256 else {
            throw PinningPreparation.failure("恢复引用与独立基线不符")
        }
        for name in RecoveryBaselineStore.fileNames {
            try FileManager.default.copyItem(at: baseline.appendingPathComponent(name), to: session.directory.appendingPathComponent(name))
        }
        try data.write(to: session.directory.appendingPathComponent(ControlledRuleChange.referenceFileName), options: .atomic)
        return reference
    }

    func finishRestore() throws { try FileManager.default.removeItem(at: recoveryURL) }

    func recoveryPending() throws -> Bool {
        var info = stat()
        if lstat(recoveryURL.path, &info) == 0 { return true }
        guard errno == ENOENT else { throw PinningPreparation.failure("无法读取恢复引用状态：errno=\(errno)") }
        return false
    }

    func loadReport(_ session: DiagnosticSession) throws -> DiagnosticReport? {
        guard FileManager.default.fileExists(atPath: session.reportURL.path) else { return nil }
        let report = try DiagnosticEncoding.decoder().decode(
            DiagnosticReport.self, from: boundedData(session.reportURL, limit: 16 * 1024 * 1024)
        )
        guard report.sessionID == session.id else { throw PinningPreparation.failure("报告与本次记录不符") }
        return report
    }

    func feedbackFiles(_ session: DiagnosticSession?) throws -> [String: Data] {
        let report = try session.flatMap { try loadReport($0) }
        let metadata = try session.map {
            try DiagnosticEncoding.decoder().decode(
                DiagnosticSessionMetadata.self, from: boundedData($0.directory.appendingPathComponent("session.json"), limit: 4096)
            )
        }
        guard metadata?.sessionID == session?.id else { throw PinningPreparation.failure("反馈记录标识不符") }
        var progress: RuleChangeResult?
        if let session {
            let url = session.directory.appendingPathComponent(ControlledRuleChange.progressFileName)
            if FileManager.default.fileExists(atPath: url.path) {
                progress = try DiagnosticEncoding.decoder().decode(
                    RuleChangeResult.self, from: boundedData(url, limit: 64 * 1024)
                )
            }
        }
        var logs: [FeedbackArchive.LogInput] = []
        var inputs = [("application", rootDirectory.appendingPathComponent("app.log"))]
        if let session { inputs += [("app", session.appLogURL), ("worker", session.workerLogURL)] }
        for (source, url) in inputs where FileManager.default.fileExists(atPath: url.path) {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular else {
                throw PinningPreparation.failure("拒绝读取非普通日志文件")
            }
            let handle = try FileHandle(forReadingFrom: url)
            let bytes: Data
            let length: UInt64
            do {
                length = try handle.seekToEnd()
                try handle.seek(toOffset: length > 128 * 1024 ? length - 128 * 1024 : 0)
                bytes = try handle.read(upToCount: 128 * 1024) ?? Data()
                try handle.close()
            } catch {
                try handle.close()
                throw error
            }
            logs.append(.init(source: source, text: String(decoding: bytes, as: UTF8.self), truncated: length > 128 * 1024))
        }
        return try FeedbackArchive.files(report: report, progress: progress, recoveryPending: recoveryPending(), logs: logs, operation: metadata?.operation)
    }

    func saveFeedback(_ data: Data) throws -> URL {
        let directory = exportDirectory.appendingPathComponent("Feedback", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(FeedbackArchive.filename())
        try data.write(to: url, options: .withoutOverwriting)
        guard try Data(contentsOf: url) == data else { throw PinningPreparation.failure("反馈包回读校验失败") }
        try applicationLogger.append("脱敏反馈 ZIP 已校验；不包含原始日志或数据库")
        return url
    }

    private func boundedData(_ url: URL, limit: Int) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? NSNumber, size.int64Value <= limit else {
            throw PinningPreparation.failure("记录不是有效普通文件或超过安全大小")
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: limit + 1) ?? Data()
        guard data.count <= limit else { throw PinningPreparation.failure("读取期间记录超过安全大小") }
        return data
    }
}
