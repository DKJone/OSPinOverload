import Foundation
import OSPinCore

let arguments = CommandLine.arguments
let preview = arguments.count == 6 && arguments[5] == "--preview"
guard (arguments.count == 5 || preview), arguments[1] == "--input", arguments[3] == "--output" else {
    fputs("Usage: ospin-inspect --input DATABASE --output NEW_DIRECTORY [--preview]\n", stderr)
    exit(64)
}
let source = URL(fileURLWithPath: arguments[2]).standardizedFileURL
let output = URL(fileURLWithPath: arguments[4]).standardizedFileURL
do {
    guard !FileManager.default.fileExists(atPath: output.path) else {
        throw NSError(domain: "OSPinInspect", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "输出目录必须不存在，避免覆盖已有文件"
        ])
    }
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    var logs: [String] = []
    let envelope = DiagnosticEngine.inspect(path: source.path, sessionID: UUID(), requireRoot: false) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) [worker \(DiagnosticAppVersion.logTag)] \($0)"
        logs.append(line)
        fputs("\(line)\n", stderr)
    }
    try DiagnosticEncoding.encoder(pretty: true).encode(envelope.report)
        .write(to: output.appendingPathComponent("report.json"), options: .atomic)
    try Data(DiagnosticSummary.text(envelope.report).utf8)
        .write(to: output.appendingPathComponent("summary.txt"), options: .atomic)
    try Data(logs.joined(separator: "\n").utf8)
        .write(to: output.appendingPathComponent("worker.log"), options: .atomic)
    if let snapshot = envelope.snapshot {
        try snapshot.write(to: output.appendingPathComponent("pinningrules.snapshot.sqlite3"), options: .atomic)
    }
    if preview {
        _ = try RecoveryBaselineStore.save(envelope, directory: output.appendingPathComponent("Baseline"))
        guard let snapshot = envelope.snapshot else {
            throw NSError(domain: "OSPinInspect", code: 2, userInfo: [NSLocalizedDescriptionKey: "未生成可预览基线"])
        }
        let plan = try PinningPreparation.createOfflinePlan(
            snapshot: snapshot, report: envelope.report, directory: output.appendingPathComponent("Plan")
        )
        print("Offline preview: \(plan.originalRuleCount) -> \(plan.candidateRuleCount), logical restore verified; source opened READONLY only")
    }
    print("Report: \(output.path), status: \(envelope.report.status.rawValue)")
    exit(envelope.report.status == .failed ? 2 : 0)
} catch {
    fputs("ERROR: \(error.localizedDescription)\n", stderr)
    exit(1)
}
