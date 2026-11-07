import Foundation

public enum DiagnosticAppVersion {
    public static let current = "1.0.2"
    public static let build = "10"
    public static let logTag = "version=\(current) build=\(build)"
}

public struct DiagnosticSessionMetadata: Codable {
    public let sessionID: UUID
    public let appVersion: String
    public let appBuild: String
    public let operation: DiagnosticOperation?

    public init(sessionID: UUID, operation: DiagnosticOperation = .diagnose) {
        self.sessionID = sessionID
        appVersion = DiagnosticAppVersion.current
        appBuild = DiagnosticAppVersion.build
        self.operation = operation
    }
}

public enum DiagnosticOperation: String, Codable {
    case diagnose, prepare, permissions, apply, restore
}

public enum DiagnosticStatus: String, Codable {
    case complete, partial, failed
}

public enum CheckLevel: String, Codable {
    case pass, warning, fail
}

public struct DiagnosticCheck: Codable {
    public let name: String
    public let level: CheckLevel
    public let detail: String
}

public struct ProcessIdentity: Codable, Equatable {
    public let uid: UInt32
    public let effectiveUID: UInt32
    public let gid: UInt32
    public let effectiveGID: UInt32
    public let pid: Int32
}

public struct DeviceInformation: Codable {
    public let machine: String
    public let systemVersion: String
    public let systemBuild: String
}

public struct DatabaseInformation: Codable {
    public let sourcePath: String
    public var fileSize: Int64?
    public var ownerID: UInt32?
    public var groupID: UInt32?
    public var posixPermissions: String?
    public var fileID: UInt64?
    public var deviceID: UInt64?
    public var schemaVersion: Int64?
    public var contentVersion: Int64?
    public var ruleCount: Int64?
    public var journalMode: String?
    public var snapshotByteCount: Int?
    public var snapshotSHA256: String?
    public var writeAccess: String
}

public struct PinningRule: Codable {
    public let policyName: String
    public let domainSuffix: String
    public let labelRegex: String
    public let transparentConnection: Int64?
    public let policiesPropertyListXML: String
    public let policiesJSON: String
    public let sourceFingerprint: String?
}

public struct HostRuleMatch: Codable {
    public let hostname: String
    public let rules: [PinningRule]
}

public struct DiagnosticReport: Codable {
    public let reportFormatVersion: Int
    public let appVersion: String
    public let appBuild: String?
    public let sessionID: UUID
    public let startedAt: Date
    public var finishedAt: Date
    public var status: DiagnosticStatus
    public let identity: ProcessIdentity
    public let device: DeviceInformation
    public var database: DatabaseInformation
    public var checks: [DiagnosticCheck]
    public var hostMatches: [HostRuleMatch]
    public var preparation: PreparationResult?
    public var operation: DiagnosticOperation?
    public var accessProbes: [FileAccessProbe]?
    public var accessFailures: [FileAccessFailure]?
    public var change: RuleChangeResult?
    public let limitations: [String]
}

public struct DiagnosticEnvelope: Codable {
    public let report: DiagnosticReport
    public let snapshot: Data?
}

public enum DiagnosticEncoding {
    public static func encoder(pretty: Bool = false) -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return encoder
    }

    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
