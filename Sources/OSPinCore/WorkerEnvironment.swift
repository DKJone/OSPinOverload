import Foundation

public enum WorkerEnvironment {
    public static func make(current: [String: String], simulator: Bool) -> [String] {
        var environment = current
        if !simulator {
            // Preserve launch/runtime state without propagating library injection into a root worker.
            for key in environment.keys.filter({ $0.hasPrefix("DYLD_") }) {
                environment.removeValue(forKey: key)
            }
        }
        return environment.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
    }
}
