import Foundation

public struct OperationPresentation {
    public enum Tone { case neutral, success, attention }
    public let title: String
    public let message: String
    public let symbol: String
    public let tone: Tone
    public let blocksEnabling: Bool

    public init(report: DiagnosticReport?, recoveryPending: Bool, restartedSinceChange: Bool = false) {
        if let change = report?.change {
            if change.verified && report?.status == .complete {
                if change.action == .apply && change.commitState == .committed && recoveryPending {
                    self.init(restartedSinceChange ? "兼容设置已启用" : "已启用，请重启手机",
                              restartedSinceChange ? "已记录上次成功结果。现在可以打开定位软件测试；系统更新后若失效，请先检查或发送反馈。" : "规则已调整并完成核对。请手动重启手机，解锁后打开定位软件设置位置。",
                              "checkmark.shield.fill", .success)
                    return
                }
                if change.action == .restore && (change.commitState == .committed || change.alreadyRestored) {
                    self.init(restartedSinceChange ? "已恢复原始设置" : "已恢复，请重启手机",
                              restartedSinceChange ? "已记录上次恢复成功结果。需要调整兼容设置时，可以重新启用。" : "原始规则已核对。请手动重启手机，让系统重新加载设置。",
                              "arrow.uturn.backward.circle.fill", .success)
                    return
                }
            }
            if [.committing, .committed, .unknown].contains(change.commitState) {
                self.init("结果需要确认", "操作可能已经生效，请勿重复启用。保留备份，前往帮助与反馈分享诊断包。", "exclamationmark.shield.fill", .attention, blocksEnabling: true)
                return
            }
            if change.action == .restore && report?.status == .failed {
                self.init("尚未恢复原始设置", "本次未提交恢复，重启不能代替恢复操作。保留备份，前往帮助与反馈发送诊断包；请勿重复启用或手动覆盖数据库。",
                          "exclamationmark.shield.fill", .attention, blocksEnabling: true)
                return
            }
        }
        if recoveryPending {
            self.init("已有待处理的备份", "请勿重复启用。可恢复原始设置；如上次操作中断，请先分享反馈包。", "shield.lefthalf.filled", .attention, blocksEnabling: true)
        } else if let report, report.status != .complete {
            let rootFailed = report.checks.contains { $0.name == "root_identity" && $0.level == .fail }
            self.init(rootFailed ? "未取得所需权限" : "操作未完成",
                      rootFailed ? "请通过 TrollStore 安装，解锁手机后重试。普通侧载不支持此功能。" : "为保护系统，本次未确认成功。请前往帮助与反馈分享诊断包，不要手动覆盖系统数据库。",
                      "exclamationmark.circle.fill", .attention)
        } else if let report, report.operation == .diagnose {
            let hasTarget = (try? PinningPreparation.targetRule(in: report)) != nil
            self.init(hasTarget ? "找到可检查的定位规则" : "暂未找到可调整的规则",
                      hasTarget ? "可以尝试启用。启用时还会检查数据库兼容性、自动备份并验证修改结果。" : "这不等于已启用。可能无需处理或当前规则格式不同；可分享诊断包协助确认。",
                      "magnifyingglass.circle.fill", hasTarget ? .neutral : .attention)
        } else if let report, [.prepare, .permissions].contains(report.operation) {
            self.init("检查已完成", "尚未提交规则变更。可返回启用兼容设置，或在帮助与反馈中分享检查结果。", "checkmark.circle.fill", .neutral)
        } else {
            self.init("准备好开始", "为受支持的定位软件调整系统兼容设置。本工具不直接设置坐标。", "location.circle.fill", .neutral)
        }
    }

    private init(_ title: String, _ message: String, _ symbol: String, _ tone: Tone, blocksEnabling: Bool = false) {
        self.title = title
        self.message = message
        self.symbol = symbol
        self.tone = tone
        self.blocksEnabling = blocksEnabling
    }
}
