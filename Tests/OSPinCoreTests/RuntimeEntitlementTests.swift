import Darwin
import Foundation
import XCTest
@testable import OSPinCore

final class RuntimeEntitlementTests: XCTestCase {
    private func blob(_ payload: Data) -> [UInt8] {
        let length = UInt32(payload.count + 8)
        return [0xfa, 0xde, 0x71, 0x71] + (0..<4).map { UInt8(truncatingIfNeeded: length >> (24 - $0 * 8)) } + payload
    }

    private func capture(_ blob: [UInt8], readError: Int32 = 0) -> RuntimeEntitlementEvidence {
        RuntimeEntitlement.capture { buffer in
            if buffer.count == 8 {
                let length = UInt32(blob.count)
                for index in 0..<4 { buffer[index + 4] = UInt8(truncatingIfNeeded: length >> (24 - index * 8)) }
                return (-1, ERANGE)
            }
            if readError != 0 { return (-1, readError) }
            buffer.copyBytes(from: blob)
            return (0, 0)
        }
    }

    private func plist(_ value: Any) throws -> [UInt8] {
        blob(try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0))
    }

    func testTrueAndFalseAreReadAsBooleanWithoutTreatingFalseAsMissing() throws {
        for value in [true, false] {
            let evidence = capture(try plist([RuntimeEntitlement.key: value, "unrelated": "not exported"]))
            XCTAssertEqual(evidence.state, .boolean)
            XCTAssertEqual(evidence.value, value)
            XCTAssertEqual(evidence.probeErrno, ERANGE)
            XCTAssertEqual(evidence.readErrno, 0)
            XCTAssertTrue(evidence.isConsistent)
            let json = String(decoding: try DiagnosticEncoding.encoder().encode(evidence), as: UTF8.self)
            XCTAssertFalse(json.contains("not exported"))
        }
    }

    func testMissingKeyRequiresSuccessfullyParsedDictionary() throws {
        let evidence = capture(try plist(["other": true]))
        XCTAssertEqual(evidence.state, .absent)
        XCTAssertNil(evidence.value)
        XCTAssertTrue(evidence.isConsistent)
    }

    func testTrailingNullInSignedXMLIsHandledWithoutInventingAValue() throws {
        let xml = try PropertyListSerialization.data(
            fromPropertyList: [RuntimeEntitlement.key: true], format: .xml, options: 0
        )
        let evidence = capture(blob(xml + Data([0])))
        XCTAssertEqual(evidence.state, .boolean)
        XCTAssertEqual(evidence.value, true)
    }

    func testNumbersStringsAndArraysAreNotCoercedToBoolean() throws {
        let values: [Any] = [NSNumber(value: 1), "true", [true]]
        for value in values {
            let evidence = capture(try plist([RuntimeEntitlement.key: value]))
            XCTAssertEqual(evidence.state, .unavailable)
            XCTAssertNil(evidence.value)
        }
    }

    func testProbeFailurePreservesErrnoAndNeverRequestsFullBlob() {
        var calls = 0
        let evidence = RuntimeEntitlement.capture { _ in
            calls += 1
            return (-1, EPERM)
        }
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(evidence.state, .unavailable)
        XCTAssertEqual(evidence.probeErrno, EPERM)
        XCTAssertNil(evidence.readReturnValue)
        XCTAssertNil(evidence.value)
        XCTAssertTrue(evidence.isConsistent)
    }

    func testFullReadFailureIsNotReportedAsMissingEntitlement() throws {
        let evidence = capture(try plist([RuntimeEntitlement.key: true]), readError: EACCES)
        XCTAssertEqual(evidence.state, .unavailable)
        XCTAssertEqual(evidence.readReturnValue, -1)
        XCTAssertEqual(evidence.readErrno, EACCES)
        XCTAssertNil(evidence.value)
    }

    func testEmptyAndOversizedKernelLengthDoNotAllocateFullBuffer() {
        for length: UInt32 in [0, 8, UInt32(RuntimeEntitlement.maximumBlobBytes + 1)] {
            var calls = 0
            let evidence = RuntimeEntitlement.capture { buffer in
                calls += 1
                for index in 0..<4 { buffer[index + 4] = UInt8(truncatingIfNeeded: length >> (24 - index * 8)) }
                return (0, 0)
            }
            XCTAssertEqual(calls, 1)
            XCTAssertEqual(evidence.state, .unavailable)
            XCTAssertNil(evidence.value)
        }
    }

    func testBadMagicChangedLengthAndInvalidPlistsRemainExplicitlyUnavailable() throws {
        var magic = try plist([RuntimeEntitlement.key: true])
        magic[0] = 0
        var length = try plist([RuntimeEntitlement.key: true])
        length[7] ^= 1
        for malformed in [magic, length, blob(Data("not a plist".utf8)), try plist(["not a dictionary"])] {
            let evidence = capture(malformed)
            XCTAssertEqual(evidence.state, .unavailable)
            XCTAssertNil(evidence.value)
        }
    }

    func testNativeSelfQueryRecordsActualProcessAndNeverInventsTrueOnFailure() {
        let evidence = RuntimeEntitlement.captureSelf()
        XCTAssertEqual(evidence.processID, getpid())
        XCTAssertEqual(evidence.key, RuntimeEntitlement.key)
        XCTAssertTrue(evidence.isConsistent)
        if evidence.state != .boolean { XCTAssertNil(evidence.value) }
    }

    func testSignedDeclarationContainsOnlyExistingKeysPlusSingleStorageKey() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let object = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: root.appendingPathComponent("Resources/OSPinOverload.entitlements")), format: nil
        )
        let dictionary = try XCTUnwrap(object as? [String: Any])
        XCTAssertEqual(Set(dictionary.keys), Set([
            "application-identifier", "platform-application", "com.apple.private.persona-mgmt",
            "com.apple.private.security.no-sandbox", "com.apple.private.security.container-required",
            RuntimeEntitlement.key
        ]))
        XCTAssertEqual(dictionary[RuntimeEntitlement.key] as? Bool, true)
    }
}
