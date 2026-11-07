import UIKit
import UniformTypeIdentifiers

final class SupportViewController: UIViewController {
    private let store: SessionStore
    private let session: DiagnosticSession?
    private let operation: (DiagnosticOperation) -> Void
    private let preview = UITextView()
    private let shareButton = UIButton(type: .system)
    private let advancedButton = UIButton(type: .system)
    private let status = UILabel()
    private var working = false
    #if DEBUG && targetEnvironment(simulator)
    private var smokeStarted = false
    #endif

    init(store: SessionStore, session: DiagnosticSession?, operation: @escaping (DiagnosticOperation) -> Void) {
        self.store = store
        self.session = session
        self.operation = operation
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "帮助与反馈"
        navigationItem.largeTitleDisplayMode = .never
        view.backgroundColor = .systemGroupedBackground
        preview.isEditable = false
        preview.font = .preferredFont(forTextStyle: .body)
        preview.adjustsFontForContentSizeCategory = true
        preview.backgroundColor = .secondarySystemGroupedBackground
        preview.layer.cornerRadius = 18
        preview.textContainerInset = UIEdgeInsets(top: 18, left: 12, bottom: 18, right: 12)
        preview.text = """
        使用方法
        启用 → 手动完整重启手机 → 打开 WLoc / MyLoc 测试位置。
        需要撤销时，选择“恢复原始设置”，完成后再次重启。

        适用范围
        通过 TrollStore 安装，首次解锁后使用。最低 iOS 15；目前仅 iOS 15.7.1 真机验证。其他版本会先检查兼容性，不保证可用。
        本工具不安装定位软件、证书，也不直接设置坐标。请先按定位软件说明安装并信任其证书。

        安全与备份
        只调整两个定位域名的一条共享规则，不关闭全局 TLS 验证、不自动重启或拦截系统更新。系统更新可能使规则重新出现。
        不兼容、系统更新或备份不符时停止，不强行覆盖。不要删除应用、备份目录或手动替换系统数据库。
        如果提示结果需要确认，请勿重复启用，先发送反馈。

        反馈包内容
        仅包含软件/设备型号/系统版本、检查状态和脱敏阶段事件。
        不包含坐标、WiFi/MAC、网络正文、证书策略、设备唯一标识、原始日志或任何数据库与备份。原始证据仍保留在本机。
        无需联网或账户；仅在你选择接收软件后分享。
        分享兼容性
        系统面板已关闭隔空投送，以避开旧系统的图标渲染崩溃；其他接收软件仍可选。
        如分享仍异常，可在下方“高级诊断与本机导出”选择“仅保存脱敏 ZIP”，再通过 Filza/USB 获取此 ZIP。
        """
        status.font = .preferredFont(forTextStyle: .footnote)
        status.numberOfLines = 0
        status.textColor = .secondaryLabel
        status.text = "分享前可查看脱敏摘要。取消分享不会影响兼容设置。"
        var config = UIButton.Configuration.filled()
        config.title = "分享脱敏反馈 ZIP"
        config.image = UIImage(systemName: "square.and.arrow.up")
        config.imagePadding = 8
        config.cornerStyle = .large
        config.contentInsets = NSDirectionalEdgeInsets(top: 16, leading: 12, bottom: 16, trailing: 12)
        shareButton.configuration = config
        shareButton.accessibilityIdentifier = "support.share"
        shareButton.addTarget(self, action: #selector(confirmShare), for: .touchUpInside)
        advancedButton.setTitle("高级诊断与本机导出", for: .normal)
        advancedButton.addTarget(self, action: #selector(showAdvanced), for: .touchUpInside)
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "脱敏摘要", style: .plain, target: self, action: #selector(showPreview))
        let stack = UIStackView(arrangedSubviews: [preview, status, shareButton, advancedButton])
        stack.axis = .vertical
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        let scroll = UIScrollView()
        scroll.alwaysBounceVertical = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)
        scroll.addSubview(stack)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -16),
            stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40),
            preview.heightAnchor.constraint(equalTo: view.safeAreaLayoutGuide.heightAnchor, multiplier: 0.6),
            preview.heightAnchor.constraint(greaterThanOrEqualToConstant: 100)
        ])
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        #if DEBUG && targetEnvironment(simulator)
        if CommandLine.arguments.contains("--smoke-test-feedback"), !smokeStarted {
            smokeStarted = true
            makeFeedback(share: CommandLine.arguments.contains("--smoke-test-share"))
        }
        #endif
    }

    @objc private func showPreview() {
        do {
            let files = try store.feedbackFiles(session)
            guard let notice = files["PRIVACY.txt"], let summary = files["feedback.json"] else {
                throw PinningPreparation.failure("反馈摘要缺少必要文件")
            }
            preview.text = String(decoding: notice, as: UTF8.self) +
                "\n\n" + String(decoding: summary, as: UTF8.self)
        } catch { failure(error) }
    }

    @objc private func confirmShare() {
        let alert = UIAlertController(title: "分享脱敏反馈？", message: "保留设备型号与系统版本以便排查，排除原始日志、位置和数据库。请只发送给可信的支持人员。", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "取消", style: .cancel))
        alert.addAction(UIAlertAction(title: "打包并选择接收软件", style: .default) { [weak self] _ in self?.makeFeedback(share: true) })
        present(alert, animated: true)
    }

    private func makeFeedback(share: Bool) {
        guard !working else { return }
        setWorking(true)
        status.text = "正在生成脱敏反馈包…"
        DispatchQueue.global(qos: .utility).async { [self] in
            do {
                let bytes = try FeedbackArchive.zip(files: store.feedbackFiles(session))
                let url = try store.saveFeedback(bytes)
                DispatchQueue.main.async { [self] in
                    setWorking(false)
                    status.text = share
                        ? "反馈包已保存，可重新分享；取消不会删除本机备份。"
                        : "脱敏反馈包已保存（未打开分享）：\n\(url.path)\n可用 Filza 转发此 ZIP，请勿发送其他原始证据目录。"
                    if share { presentShare(bytes, url: url) }
                }
            } catch {
                DispatchQueue.main.async { [self] in
                    setWorking(false)
                    failure(error)
                }
            }
        }
    }

    private func presentShare(_ bytes: Data, url: URL) {
        let filename = url.lastPathComponent
        let provider = NSItemProvider()
        provider.suggestedName = filename
        // A named ZIP file representation prevents generic File.zip names in file-based receivers.
        provider.registerFileRepresentation(forTypeIdentifier: UTType.zip.identifier, fileOptions: [], visibility: .all) { completion in
            completion(url, false, nil)
            return nil
        }
        provider.registerDataRepresentation(forTypeIdentifier: UTType.zip.identifier, visibility: .all) { completion in
            completion(bytes, nil)
            return nil
        }
        #if DEBUG && targetEnvironment(simulator)
        if CommandLine.arguments.contains("--smoke-test-share") {
            provider.loadFileRepresentation(forTypeIdentifier: UTType.zip.identifier) { [self] file, error in
                do {
                    if let error { throw error }
                    guard let file, file.lastPathComponent == filename, try Data(contentsOf: file) == bytes else {
                        throw PinningPreparation.failure("分享附件名称或 ZIP 内容不一致")
                    }
                    try store.applicationLogger.append("分享附件名称与 ZIP 内容已核对 filename=\(filename)")
                } catch { DispatchQueue.main.async { self.failure(error) } }
            }
        }
        #endif
        let configuration = UIActivityItemsConfiguration(itemProviders: [provider])
        configuration.metadataProvider = { key in key == .title ? filename : nil }
        let controller = UIActivityViewController(activityItemsConfiguration: configuration)
        // iOS 15 can crash in MobileIcons/CoreImage while rendering the AirDrop activity icon.
        controller.excludedActivityTypes = [.airDrop]
        controller.popoverPresentationController?.sourceView = shareButton
        controller.popoverPresentationController?.sourceRect = shareButton.bounds
        controller.completionWithItemsHandler = { [weak self] _, completed, _, error in
            if let error { self?.failure(error) }
            else { self?.status.text = completed ? "反馈包已交给所选软件，请在该软件中确认发送。" : "已取消分享。反馈包仍保留在本机，可稍后重试。" }
        }
        present(controller, animated: true) { [weak self] in
            do { try self?.store.applicationLogger.append("系统分享面板已呈现；已排除 AirDrop；未自动发送反馈") }
            catch { self?.failure(error) }
        }
    }

    @objc private func showAdvanced() {
        let sheet = UIAlertController(title: "高级诊断与本机导出", message: "仅供排查使用。下列操作不提交规则变更。", preferredStyle: .actionSheet)
        sheet.addAction(UIAlertAction(title: "仅保存脱敏 ZIP（不打开分享）", style: .default) { [weak self] _ in self?.makeFeedback(share: false) })
        sheet.addAction(UIAlertAction(title: "权限对照（不写内容）", style: .default) { [weak self] _ in self?.operation(.permissions) })
        sheet.addAction(UIAlertAction(title: "备份与回滚预检（不提交）", style: .default) { [weak self] _ in self?.operation(.prepare) })
        sheet.addAction(UIAlertAction(title: "USB 完整本机导出（含数据库）", style: .default) { [weak self] _ in self?.confirmLocalExport() })
        sheet.addAction(UIAlertAction(title: "取消", style: .cancel))
        sheet.popoverPresentationController?.sourceView = advancedButton
        sheet.popoverPresentationController?.sourceRect = advancedButton.bounds
        present(sheet, animated: true)
    }

    private func confirmLocalExport() {
        let alert = UIAlertController(title: "仅保存完整证据到本机", message: "此导出包含原始日志和系统数据库，不属于脱敏反馈包，不会传入系统分享。仅在开发者明确需要时，通过 USB 获取并妥善保管。", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "取消", style: .cancel))
        alert.addAction(UIAlertAction(title: "保存到 USB 可读目录", style: .default) { [weak self] _ in self?.localExport() })
        present(alert, animated: true)
    }

    private func localExport() {
        guard let session else {
            status.text = "尚无操作记录，请先返回首页运行一次检查。"
            return
        }
        setWorking(true)
        DispatchQueue.global(qos: .utility).async { [self] in
            do {
                let result = try store.export(session)
                DispatchQueue.main.async { [self] in
                    setWorking(false)
                    status.text = "完整证据已保存（未分享）：\n\(result.directory.path)"
                }
            } catch {
                DispatchQueue.main.async { [self] in setWorking(false); failure(error) }
            }
        }
    }

    private func setWorking(_ value: Bool) {
        working = value
        shareButton.isEnabled = !value
        advancedButton.isEnabled = !value
        navigationItem.rightBarButtonItem?.isEnabled = !value
        navigationItem.hidesBackButton = value
    }

    private func failure(_ error: Error) {
        do {
            try store.applicationLogger.append("ERROR 反馈/导出失败：\(error.localizedDescription)")
            status.text = "反馈包未能完成。请检查可用空间后重试；现有备份和兼容设置不受影响。"
        } catch {
            status.text = "反馈包和错误记录均未能保存，请检查可用空间。现有备份不会被自动删除。"
        }
    }
}
