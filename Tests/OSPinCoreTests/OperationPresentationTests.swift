import XCTest
@testable import OSPinCore

final class OperationPresentationTests: XCTestCase {
    private func report(_ action: DiagnosticOperation, state: RuleCommitState, verified: Bool) -> DiagnosticReport {
        var report = DiagnosticEngine.initialReport(sessionID: UUID(), operation: action)
        report.status = verified ? .complete : .failed
        report.change = .init(baselineID: UUID(), baselineReceiptSHA256: "", action: action, commitState: state, verified: verified)
        return report
    }

    func testVerifiedCommitPromptsManualRebootWithoutClaimingLocationSuccess() {
        let value = OperationPresentation(report: report(.apply, state: .committed, verified: true), recoveryPending: true)
        XCTAssertTrue(value.title.contains("重启"))
        XCTAssertFalse(value.message.contains("定位已恢复"))
    }

    func testUnknownAndCommittedButUnverifiedOutcomesNeverLookSuccessful() {
        for state in [RuleCommitState.unknown, .committing, .committed] {
            let value = OperationPresentation(report: report(.apply, state: state, verified: false), recoveryPending: true)
            XCTAssertEqual(value.title, "结果需要确认")
            XCTAssertTrue(value.message.contains("请勿重复启用"))
            XCTAssertTrue(value.blocksEnabling)
        }
    }

    func testReferenceAloneDoesNotClaimAppliedAndRequiresAttention() {
        let value = OperationPresentation(report: nil, recoveryPending: true)
        XCTAssertEqual(value.title, "已有待处理的备份")
        XCTAssertTrue(value.blocksEnabling)
    }

    func testRestoreCommitAndAlreadyRestoredBothHaveClearNextStep() {
        let value = OperationPresentation(report: report(.restore, state: .committed, verified: true), recoveryPending: false)
        XCTAssertEqual(value.title, "已恢复，请重启手机")
        XCTAssertTrue(value.message.contains("重启"))
        var restored = report(.restore, state: .notAttempted, verified: true)
        restored.change?.alreadyRestored = true
        XCTAssertEqual(OperationPresentation(report: restored, recoveryPending: false).title, "已恢复，请重启手机")
    }

    func testFailedRestoreNeverSuggestsThatRebootCompletesRestoration() {
        for state in [RuleCommitState.notAttempted, .rolledBack] {
            let value = OperationPresentation(report: report(.restore, state: state, verified: false), recoveryPending: true)
            XCTAssertEqual(value.title, "尚未恢复原始设置")
            XCTAssertTrue(value.message.contains("重启不能代替恢复"))
            XCTAssertTrue(value.blocksEnabling)
        }
        let value = OperationPresentation(report: report(.restore, state: .unknown, verified: false), recoveryPending: true)
        XCTAssertEqual(value.title, "结果需要确认")
    }

    func testVerifiedRestoreAfterRebootDoesNotRequestAnotherReboot() {
        let value = OperationPresentation(report: report(.restore, state: .committed, verified: true),
                                          recoveryPending: false, restartedSinceChange: true)
        XCTAssertEqual(value.title, "已恢复原始设置")
        XCTAssertFalse(value.message.contains("请手动重启"))
    }

    func testMissingTargetIsNotPresentedAsAlreadyEnabled() {
        var value = DiagnosticEngine.initialReport(sessionID: UUID(), operation: .diagnose)
        value.status = .complete
        let presentation = OperationPresentation(report: value, recoveryPending: false)
        XCTAssertTrue(presentation.title.contains("暂未找到"))
        XCTAssertTrue(presentation.message.contains("不等于已启用"))
    }

    func testPartialReportCannotBecomeIdleSuccess() {
        var value = DiagnosticEngine.initialReport(sessionID: UUID())
        value.status = .partial
        XCTAssertEqual(OperationPresentation(report: value, recoveryPending: false).title, "操作未完成")
    }

    func testRootFailureHasInstallationGuidance() {
        var value = DiagnosticEngine.initialReport(sessionID: UUID())
        value.checks = [.init(name: "root_identity", level: .fail, detail: "technical details")]
        value.status = .failed
        let presentation = OperationPresentation(report: value, recoveryPending: false)
        XCTAssertTrue(presentation.message.contains("TrollStore"))
        XCTAssertFalse(presentation.message.contains("technical details"))
    }

    func testAfterRebootDoesNotKeepRequestingAnotherReboot() {
        let value = OperationPresentation(report: report(.apply, state: .committed, verified: true),
                                          recoveryPending: true, restartedSinceChange: true)
        XCTAssertEqual(value.title, "兼容设置已启用")
        XCTAssertFalse(value.message.contains("请手动重启"))
        XCTAssertTrue(value.message.contains("上次成功"))
    }

    func testMissingRecoveryReferenceCannotLookLikeNormallyAppliedState() {
        let value = OperationPresentation(report: report(.apply, state: .committed, verified: true), recoveryPending: false)
        XCTAssertEqual(value.title, "结果需要确认")
        XCTAssertTrue(value.blocksEnabling)
    }
}
