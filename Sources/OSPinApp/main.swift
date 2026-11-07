import Darwin
import Foundation
import UIKit

if ["--diagnose", "--prepare", "--permissions", "--apply", "--restore"].contains(CommandLine.arguments.dropFirst().first ?? "") {
    guard let request = DiagnosticWorkerRequest.parse(Array(CommandLine.arguments.dropFirst())) else {
        fputs("[worker \(DiagnosticAppVersion.logTag)] ERROR invalid diagnostic arguments\n", stderr)
        exit(64)
    }
    signal(SIGPIPE, SIG_IGN)
    var logFailed = false
    let logger: (String) -> Void = { message in
        let line = "\(ISO8601DateFormatter().string(from: Date())) [worker \(DiagnosticAppVersion.logTag)] \(message)\n"
        if fputs(line, stderr) < 0 { logFailed = true }
        fflush(stderr)
    }
    var envelope: DiagnosticEnvelope
    switch request {
    case .diagnose(let sessionID): envelope = DiagnosticEngine.inspect(sessionID: sessionID, log: logger)
    case .prepare(let sessionID, let hash, let metadataHash):
        envelope = PinningPreparation.preflight(sessionID: sessionID, baselineSHA256: hash, baselineMetadataSHA256: metadataHash, log: logger)
    case .permissions(let sessionID, let profile):
        signal(SIGALRM, SIG_DFL)
        alarm(20)
        envelope = FileAccessDiagnostics.inspect(sessionID: sessionID, profile: profile, log: logger)
    case .change(let sessionID, let action, let baselineID, let hash):
        signal(SIGALRM, SIG_DFL)
        alarm(120)
        #if targetEnvironment(simulator)
        let media = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("OSPinOverload")
        #else
        let media = URL(fileURLWithPath: "/var/mobile/Media/OSPinOverload")
        #endif
        envelope = ControlledRuleChange.run(
            action: action, sessionID: sessionID,
            reference: RuleRecoveryReference(baselineID: baselineID, receiptSHA256: hash),
            baselineDirectory: media.appendingPathComponent("Baselines/\(baselineID.uuidString)"),
            persist: {
                try ControlledRuleChange.persist($0, at: media.appendingPathComponent(
                    "Diagnostics/Sessions/\(sessionID.uuidString)/\(ControlledRuleChange.progressFileName)"
                ))
            }, log: logger
        )
    }
    if logFailed {
        var report = envelope.report
        report.status = .failed
        report.accessProbes = report.accessProbes?.map {
            var probe = $0
            probe.status = .failed
            return probe
        }
        report.checks.append(DiagnosticCheck(name: "worker_log", level: .fail, detail: "helper 日志输出失败"))
        envelope = DiagnosticEnvelope(report: report, snapshot: envelope.snapshot)
    }
    do {
        let data = try DiagnosticEncoding.encoder().encode(envelope)
        try FileHandle.standardOutput.write(contentsOf: data)
        exit(envelope.report.status == .failed ? 2 : 0)
    } catch {
        fputs("[worker \(DiagnosticAppVersion.logTag)] ERROR helper report encoding/output: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
} else {
    UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(AppDelegate.self))
}
