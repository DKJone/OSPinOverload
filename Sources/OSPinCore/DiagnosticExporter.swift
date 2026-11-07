import CryptoKit
import Foundation

public struct ExportedDiagnosticFile: Codable {
    public let name: String
    public let byteCount: UInt64
    public let sha256: String
}

public struct DiagnosticExportReceipt: Codable {
    public let receiptFormatVersion: Int
    public let appVersion: String
    public let appBuild: String?
    public let sessionID: UUID
    public let exportID: UUID
    public let createdAt: Date
    public let files: [ExportedDiagnosticFile]
    public let missingSessionFiles: [String]
}

public struct DiagnosticExport {
    public let directory: URL
    public let receipt: DiagnosticExportReceipt
}

public enum DiagnosticExporter {
    private static let sessionFileNames = [
        "summary.txt", "report.json", "app.log", "worker.log", "pinningrules.snapshot.sqlite3"
    ]
    private static let preparationFileNames = [
        "baseline.sqlite3", "baseline-report.json", "baseline-receipt.json", "plan.json", "candidate.sqlite3", "restored.sqlite3"
    ]

    public static func export(
        sessionID: UUID,
        sourceDirectory: URL,
        exportRoot: URL,
        applicationLog: URL? = nil
    ) throws -> DiagnosticExport {
        var sources: [(String, URL)] = []
        var missing: [String] = []
        let hasPreparation = preparationFileNames.contains { FileManager.default.fileExists(atPath: sourceDirectory.appendingPathComponent($0).path) }
        let changeNames = [ControlledRuleChange.progressFileName, ControlledRuleChange.referenceFileName].filter {
            FileManager.default.fileExists(atPath: sourceDirectory.appendingPathComponent($0).path)
        }
        for name in sessionFileNames + (hasPreparation ? preparationFileNames : []) + changeNames {
            let source = sourceDirectory.appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: source.path) {
                sources.append((name, source))
            } else {
                missing.append(name)
            }
        }
        guard !sources.isEmpty else { throw failure("本次诊断尚未生成可导出的文件") }
        if let applicationLog { sources.append(("application.log", applicationLog)) }
        let exportID = UUID()
        let destination = exportRoot.appendingPathComponent(".pending-\(exportID.uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        var files: [ExportedDiagnosticFile] = []
        for (name, source) in sources {
            let attributes = try FileManager.default.attributesOfItem(atPath: source.path)
            guard attributes[.type] as? FileAttributeType == .typeRegular else {
                throw failure("拒绝导出非普通文件：\(name)")
            }
            let before = try digest(source)
            let target = destination.appendingPathComponent(name)
            try FileManager.default.copyItem(at: source, to: target)
            let copied = try digest(target)
            let after = try digest(source)
            guard before == copied, before == after else {
                throw failure("文件在导出期间变化或复制不完整：\(name)；现场已保留")
            }
            let size = try FileManager.default.attributesOfItem(atPath: target.path)[.size]
            guard let number = size as? NSNumber else { throw failure("无法取得导出文件大小：\(name)") }
            files.append(ExportedDiagnosticFile(name: name, byteCount: number.uint64Value, sha256: copied))
        }
        let receipt = DiagnosticExportReceipt(
            receiptFormatVersion: 1, appVersion: DiagnosticAppVersion.current,
            appBuild: DiagnosticAppVersion.build,
            sessionID: sessionID, exportID: exportID, createdAt: Date(),
            files: files, missingSessionFiles: missing
        )
        try DiagnosticEncoding.encoder(pretty: true).encode(receipt)
            .write(to: destination.appendingPathComponent("receipt.json"), options: .atomic)
        let latest = exportRoot.appendingPathComponent("Latest", isDirectory: true)
        let previous = exportRoot.appendingPathComponent(".previous-\(exportID.uuidString)", isDirectory: true)
        let hadPrevious = FileManager.default.fileExists(atPath: latest.path)
        if hadPrevious {
            let attributes = try FileManager.default.attributesOfItem(atPath: latest.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory else {
                throw failure("Latest 不是普通目录；拒绝覆盖")
            }
            try FileManager.default.moveItem(at: latest, to: previous)
        }
        do {
            try FileManager.default.moveItem(at: destination, to: latest)
        } catch {
            if hadPrevious {
                do { try FileManager.default.moveItem(at: previous, to: latest) }
                catch let rollbackError {
                    throw failure("发布失败：\(error.localizedDescription)；恢复旧导出失败：\(rollbackError.localizedDescription)")
                }
            }
            throw error
        }
        if hadPrevious { try FileManager.default.removeItem(at: previous) }
        try removeLegacyExports(in: exportRoot)
        return DiagnosticExport(directory: latest, receipt: receipt)
    }

    private static func removeLegacyExports(in root: URL) throws {
        for directory in try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) {
            guard let sessionID = UUID(uuidString: directory.lastPathComponent) else { continue }
            let attributes = try FileManager.default.attributesOfItem(atPath: directory.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory else { continue }
            let children = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            guard !children.isEmpty else { continue }
            for child in children {
                guard let exportID = UUID(uuidString: child.lastPathComponent) else {
                    throw failure("旧导出目录包含未知文件；保留现场：\(directory.lastPathComponent)")
                }
                let childAttributes = try FileManager.default.attributesOfItem(atPath: child.path)
                guard childAttributes[.type] as? FileAttributeType == .typeDirectory else {
                    throw failure("旧导出不是普通目录；拒绝清理")
                }
                let receipt = try DiagnosticEncoding.decoder().decode(
                    DiagnosticExportReceipt.self, from: Data(contentsOf: child.appendingPathComponent("receipt.json"))
                )
                guard receipt.receiptFormatVersion == 1, receipt.sessionID == sessionID, receipt.exportID == exportID else {
                    throw failure("旧导出标识不一致；拒绝清理")
                }
                let names = Set(try FileManager.default.contentsOfDirectory(atPath: child.path))
                let expected = Set(receipt.files.map(\.name)).union(["receipt.json"])
                guard names == expected, Set(receipt.files.map(\.name)).isSubset(of: Set(sessionFileNames + ["application.log"])) else {
                    throw failure("旧导出包含未知文件；拒绝清理")
                }
            }
            try FileManager.default.removeItem(at: directory)
        }
    }

    private static func digest(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hash = SHA256()
        while let data = try handle.read(upToCount: 65_536), !data.isEmpty { hash.update(data: data) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func failure(_ description: String) -> NSError {
        NSError(domain: "OSPinOverload.Export", code: 1, userInfo: [NSLocalizedDescriptionKey: description])
    }
}
