import CoreFoundation
import Darwin
import Foundation

@_silgen_name("csops")
private func readCodeSigningInformation(_ pid: pid_t, _ operation: UInt32, _ address: UnsafeMutableRawPointer?, _ size: Int) -> Int32

public enum RuntimeEntitlementState: String, Codable {
    case boolean, absent, unavailable
}

public struct RuntimeEntitlementEvidence: Codable {
    public let key: String
    public let processID: Int32
    public let method: String
    public var state: RuntimeEntitlementState
    public var value: Bool?
    public var probeReturnValue: Int32?
    public var probeErrno: Int32?
    public var readReturnValue: Int32?
    public var readErrno: Int32?
    public var blobByteCount: Int?
    public var detail: String

    public var isConsistent: Bool {
        guard key == RuntimeEntitlement.key, method == RuntimeEntitlement.method,
              processID > 0, !detail.isEmpty else { return false }
        switch state {
        case .boolean, .absent:
            return (state == .boolean ? value != nil : value == nil)
                && ((probeReturnValue == -1 && probeErrno == ERANGE) || (probeReturnValue == 0 && probeErrno == 0))
                && readReturnValue == 0 && readErrno == 0
                && blobByteCount.map { (9...RuntimeEntitlement.maximumBlobBytes).contains($0) } == true
        case .unavailable:
            return value == nil && probeReturnValue != nil && probeErrno != nil
        }
    }
}

public enum RuntimeEntitlement {
    public static let key = "com.apple.private.security.storage.trustd"
    public static let method = "csops_self_xml"
    static let maximumBlobBytes = 1024 * 1024
    private static let xmlMagic: UInt32 = 0xfade7171

    public static func captureSelf() -> RuntimeEntitlementEvidence {
        capture { buffer in
            // CS_OPS_ENTITLEMENTS_BLOB, restricted here to this process.
            let result = readCodeSigningInformation(getpid(), 7, buffer.baseAddress, buffer.count)
            return (result, result < 0 ? errno : 0)
        }
    }

    static func capture(
        query: (UnsafeMutableRawBufferPointer) -> (result: Int32, error: Int32)
    ) -> RuntimeEntitlementEvidence {
        var evidence = RuntimeEntitlementEvidence(
            key: key, processID: getpid(), method: method, state: .unavailable,
            detail: "尚未取得内核导出的自身 XML entitlement"
        )
        var header = [UInt8](repeating: 0, count: 8)
        let probe = header.withUnsafeMutableBytes { query($0) }
        evidence.probeReturnValue = probe.result
        evidence.probeErrno = probe.result == 0 ? 0 : probe.error
        guard probe.result == 0 || (probe.result == -1 && probe.error == ERANGE) else {
            evidence.detail = "csops 长度查询失败：errno=\(probe.error)"
            return evidence
        }
        // XNU may return ERANGE with only the length populated, not the magic.
        let length = Int(word(header, at: 4))
        evidence.blobByteCount = length
        guard (9...maximumBlobBytes).contains(length) else {
            evidence.detail = "自身 XML entitlement 不可用或长度越界：\(length)；不推断 key 缺失"
            return evidence
        }
        var blob = [UInt8](repeating: 0, count: length)
        let read = blob.withUnsafeMutableBytes { query($0) }
        evidence.readReturnValue = read.result
        evidence.readErrno = read.result == 0 ? 0 : read.error
        guard read.result == 0 else {
            evidence.detail = "csops 完整读取失败：errno=\(read.error)"
            return evidence
        }
        guard word(blob, at: 0) == xmlMagic, Int(word(blob, at: 4)) == length else {
            evidence.detail = "内核 XML entitlement 的 magic/长度不匹配；不使用部分数据"
            return evidence
        }
        do {
            let plist = try PropertyListSerialization.propertyList(from: Data(blob.dropFirst(8)), options: [], format: nil)
            guard let dictionary = plist as? [String: Any] else {
                evidence.detail = "内核 XML entitlement 不是字典"
                return evidence
            }
            guard let value = dictionary[key] else {
                evidence.state = .absent
                evidence.detail = "已解析内核导出的自身 entitlement 字典，目标 key 缺失"
                return evidence
            }
            guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
                evidence.detail = "目标 entitlement 不是 CFBoolean；不将数字或字符串当作授权"
                return evidence
            }
            evidence.state = .boolean
            evidence.value = number.boolValue
            evidence.detail = "内核导出目标 Boolean=\(number.boolValue)；不代表文件系统允许访问"
        } catch {
            let failure = error as NSError
            evidence.detail = "内核 XML entitlement 解析失败：domain=\(failure.domain) code=\(failure.code)"
        }
        return evidence
    }

    private static func word(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        bytes[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
}
