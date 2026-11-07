import UIKit

final class DiagnosticViewController: UIViewController {
    private let store: SessionStore
    private let runner: RootDiagnosticRunner
    private let symbol = UIImageView()
    private let statusLabel = UILabel()
    private let detailLabel = UILabel()
    private let spinner = UIActivityIndicatorView(style: .medium)
    private let applyButton = UIButton(type: .system)
    private let restoreButton = UIButton(type: .system)
    private let checkButton = UIButton(type: .system)
    private let projectButton = UIButton(type: .system)
    private let projectAddress = "https://github.com/DKJone/OSPinOverload"
    private let scroll = UIScrollView()
    private var session: DiagnosticSession?
    private var report: DiagnosticReport?
    private var pending = false
    private var busy = false
    private var storageReady = true
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    #if DEBUG && targetEnvironment(simulator)
    private var didRunSmokeTest = false
    #endif

    init(store: SessionStore) {
        self.store = store
        runner = RootDiagnosticRunner(store: store)
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "OSPinOverload"
        navigationController?.navigationBar.prefersLargeTitles = true
        navigationItem.backButtonDisplayMode = .minimal
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "questionmark.circle"), style: .plain, target: self, action: #selector(showSupport)
        )
        navigationItem.rightBarButtonItem?.accessibilityLabel = "帮助与反馈"
        view.backgroundColor = .systemGroupedBackground
        scroll.alwaysBounceVertical = true
        scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll)
        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(stack)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -30),
            stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -40)
        ])
        symbol.contentMode = .scaleAspectFit
        symbol.preferredSymbolConfiguration = UIImage.SymbolConfiguration(pointSize: 54, weight: .medium)
        symbol.heightAnchor.constraint(equalToConstant: 70).isActive = true
        statusLabel.font = .preferredFont(forTextStyle: .title2)
        statusLabel.adjustsFontForContentSizeCategory = true
        statusLabel.numberOfLines = 0
        statusLabel.accessibilityIdentifier = "home.status"
        detailLabel.font = .preferredFont(forTextStyle: .body)
        detailLabel.adjustsFontForContentSizeCategory = true
        detailLabel.textColor = .secondaryLabel
        detailLabel.numberOfLines = 0
        detailLabel.accessibilityIdentifier = "home.nextStep"
        spinner.hidesWhenStopped = true
        stack.addArrangedSubview(card([symbol, statusLabel, detailLabel, spinner]))
        configure(applyButton, title: "启用定位兼容", symbol: "checkmark.shield", filled: true)
        configure(restoreButton, title: "恢复原始设置", symbol: "arrow.uturn.backward", filled: false)
        configure(checkButton, title: "仅检查，不修改", symbol: "magnifyingglass", filled: false)
        applyButton.accessibilityIdentifier = "home.enable"
        restoreButton.accessibilityIdentifier = "home.restore"
        applyButton.addTarget(self, action: #selector(applyRule), for: .touchUpInside)
        restoreButton.addTarget(self, action: #selector(restoreRule), for: .touchUpInside)
        checkButton.addTarget(self, action: #selector(checkCompatibility), for: .touchUpInside)
        stack.addArrangedSubview(card([applyButton, restoreButton, checkButton]))
        stack.addArrangedSubview(card([
            label("三步开始使用", style: .headline),
            label("1  启用兼容设置，自动检查并保存备份。"),
            label("2  手动重启手机，再次解锁。"),
            label("3  打开 WLoc / MyLoc 设置位置并测试。")
        ]))
        stack.addArrangedSubview(label("仅用于本人或已获授权的设备。会降低两个 Apple 定位域名的证书固定约束；不会关闭全局 TLS 验证。", style: .footnote))
        stack.addArrangedSubview(label("版本 \(DiagnosticAppVersion.current) · TrollStore 专用", style: .footnote))
        var projectConfig = UIButton.Configuration.plain()
        projectConfig.title = "GitHub 项目主页"
        projectConfig.subtitle = projectAddress
        projectConfig.image = UIImage(systemName: "arrow.up.right")
        projectConfig.imagePlacement = .trailing
        projectConfig.imagePadding = 12
        projectConfig.titleAlignment = .leading
        projectConfig.subtitleLineBreakMode = .byCharWrapping
        projectConfig.baseForegroundColor = .systemBlue
        projectConfig.background.backgroundColor = .secondarySystemGroupedBackground
        projectConfig.background.cornerRadius = 24
        projectConfig.cornerStyle = .fixed
        projectConfig.contentInsets = NSDirectionalEdgeInsets(top: 20, leading: 20, bottom: 20, trailing: 20)
        projectConfig.subtitleTextAttributesTransformer = UIConfigurationTextAttributesTransformer { incoming in
            var attributes = incoming
            attributes.foregroundColor = .secondaryLabel
            attributes.font = .preferredFont(forTextStyle: .footnote)
            return attributes
        }
        projectButton.configuration = projectConfig
        projectButton.contentHorizontalAlignment = .leading
        projectButton.titleLabel?.adjustsFontForContentSizeCategory = true
        projectButton.subtitleLabel?.adjustsFontForContentSizeCategory = true
        projectButton.accessibilityIdentifier = "home.github"
        projectButton.accessibilityHint = "打开 GitHub 项目主页，查看源码、使用说明和版本更新"
        projectButton.accessibilityTraits.insert(.link)
        projectButton.addTarget(self, action: #selector(openProjectHome), for: .touchUpInside)
        stack.addArrangedSubview(projectButton)
        reloadState()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        #if DEBUG && targetEnvironment(simulator)
        guard !didRunSmokeTest else { return }
        if CommandLine.arguments.contains("--smoke-test-home-footer") || CommandLine.arguments.contains("--smoke-test-project-link") {
            didRunSmokeTest = true
            view.layoutIfNeeded()
            scroll.scrollRectToVisible(projectButton.convert(projectButton.bounds, to: scroll), animated: false)
            if CommandLine.arguments.contains("--smoke-test-project-link") {
                projectButton.sendActions(for: .touchUpInside)
            }
            return
        }
        if CommandLine.arguments.contains("--smoke-test-feedback") {
            didRunSmokeTest = true
            showSupport()
            return
        }
        for operation in [DiagnosticOperation.diagnose, .prepare, .permissions, .apply] {
            if CommandLine.arguments.contains("--smoke-test-\(operation.rawValue)") {
                didRunSmokeTest = true
                runOperation(operation)
                return
            }
        }
        #endif
    }

    private func reloadState() {
        do {
            session = try store.latestSession()
            report = try session.flatMap { try store.loadReport($0) }
            pending = try store.recoveryPending()
            storageReady = true
            render()
        } catch {
            storageReady = false
            render()
            statusLabel.text = "记录暂时无法读取"
            detailLabel.text = "为保护已有备份，已暂停操作。请前往帮助与反馈；不要删除应用或覆盖系统数据库。"
            logFailure(error)
        }
    }

    private func render() {
        let rebooted = report.map { $0.finishedAt < Date().addingTimeInterval(-ProcessInfo.processInfo.systemUptime) } ?? false
        let feedback = OperationPresentation(report: report, recoveryPending: pending, restartedSinceChange: rebooted)
        statusLabel.text = feedback.title
        detailLabel.text = feedback.message
        symbol.image = UIImage(systemName: feedback.symbol)
        switch feedback.tone {
        case .neutral: symbol.tintColor = .systemBlue
        case .success: symbol.tintColor = .systemTeal
        case .attention: symbol.tintColor = .systemOrange
        }
        applyButton.isEnabled = !busy && storageReady && !pending && !feedback.blocksEnabling
        restoreButton.isEnabled = !busy && storageReady && pending
        checkButton.isEnabled = !busy && storageReady
        navigationItem.rightBarButtonItem?.isEnabled = !busy
        projectButton.isEnabled = !busy
        busy ? spinner.startAnimating() : spinner.stopAnimating()
    }

    @objc private func applyRule() { confirmChange(.apply) }
    @objc private func restoreRule() { confirmChange(.restore) }
    @objc private func checkCompatibility() { runOperation(.diagnose) }

    @objc private func openProjectHome() {
        guard let url = URL(string: projectAddress) else {
            showProjectOpenFailure()
            return
        }
        UIApplication.shared.open(url, options: [:]) { [weak self] opened in
            DispatchQueue.main.async {
                guard let self else { return }
                guard opened else { self.showProjectOpenFailure(); return }
                #if DEBUG && targetEnvironment(simulator)
                do { try self.store.applicationLogger.append("项目主页链接已交给系统 url=\(url.absoluteString)") }
                catch { self.logFailure(error) }
                #endif
            }
        }
    }

    private func showProjectOpenFailure() {
        let alert = UIAlertController(title: "暂时无法打开项目主页", message: "请在浏览器中访问：\n\(projectAddress)", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "知道了", style: .default))
        present(alert, animated: true)
    }

    private func confirmChange(_ operation: DiagnosticOperation) {
        let applying = operation == .apply
        let alert = UIAlertController(
            title: applying ? "启用定位兼容？" : "恢复原始设置？",
            message: applying
                ? "将自动检查、备份并调整两个 Apple 定位域名的一条共享规则。这会降低这两个域名的证书固定约束，但不会关闭全局 TLS 验证。\n\n完成后请手动重启手机，再打开定位软件测试。若设备或数据库不兼容，将停止而不强行修改。请保持应用在前台。"
                : "将使用本机备份恢复原始规则。完成后请手动重启手机。\n\n如果系统已经更新或数据不符，会停止操作以避免覆盖新内容；不会替换整个数据库。",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "取消", style: .cancel))
        alert.addAction(UIAlertAction(title: applying ? "备份并启用" : "确认恢复", style: applying ? .destructive : .default) { [weak self] _ in
            self?.runOperation(operation)
        })
        present(alert, animated: true)
    }

    private func runOperation(_ operation: DiagnosticOperation) {
        guard !busy else { return }
        do {
            let session = try store.createSession(operation: operation)
            self.session = session
            busy = true
            render()
            statusLabel.text = operation == .restore ? "正在恢复…" : operation == .apply ? "正在检查并启用…" : "正在检查…"
            detailLabel.text = "请保持应用在前台，暂时不要重启手机。完成后会提示下一步。"
            backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "PinningOperation") { [weak self] in
                self?.endBackgroundTask()
            }
            runner.run(session: session, operation: operation, progress: { [weak self] text in
                self?.statusLabel.text = text
            }) { [weak self] result in
                guard let self else { return }
                self.endBackgroundTask()
                self.busy = false
                self.reloadState()
                if case .failure(let error) = result {
                    self.statusLabel.text = "操作未完成"
                    self.detailLabel.text = self.pending
                        ? "请勿重复启用。保留备份，前往帮助与反馈分享诊断包。"
                        : "请确认已使用 TrollStore 安装并解锁手机。仍无法完成时，请分享反馈包。"
                    self.logFailure(error)
                }
                if case .success(let report) = result, report.status == .complete, report.change?.verified == true {
                    let feedback = OperationPresentation(report: report, recoveryPending: self.pending)
                    if case .success = feedback.tone {
                        let alert = UIAlertController(title: feedback.title, message: feedback.message, preferredStyle: .alert)
                        alert.addAction(UIAlertAction(title: "知道了，稍后手动重启", style: .default))
                        self.present(alert, animated: true)
                    }
                }
                #if DEBUG && targetEnvironment(simulator)
                if CommandLine.arguments.contains("--smoke-test-export") { self.exportForSmokeTest(session) }
                #endif
            }
        } catch {
            busy = false
            render()
            statusLabel.text = "无法开始操作"
            detailLabel.text = "无法保存本机记录，已停止操作。请检查存储空间并前往帮助与反馈。"
            logFailure(error)
        }
    }

    @objc private func showSupport() {
        let controller = SupportViewController(store: store, session: session) { [weak self] operation in
            self?.navigationController?.popViewController(animated: true)
            self?.runOperation(operation)
        }
        navigationController?.pushViewController(controller, animated: true)
    }

    private func endBackgroundTask() {
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    private func logFailure(_ error: Error) {
        do { try store.applicationLogger.append("ERROR \(error.localizedDescription)") }
        catch {
            detailLabel.text = (detailLabel.text ?? "") + "\n错误记录也未能保存，请检查可用存储空间。"
        }
    }

    #if DEBUG && targetEnvironment(simulator)
    private func exportForSmokeTest(_ session: DiagnosticSession) {
        DispatchQueue.global(qos: .utility).async { [self] in
            do { _ = try store.export(session) }
            catch { DispatchQueue.main.async { self.logFailure(error) } }
        }
    }
    #endif

    private func configure(_ button: UIButton, title: String, symbol: String, filled: Bool) {
        var config = filled ? UIButton.Configuration.filled() : .tinted()
        config.title = title
        config.image = UIImage(systemName: symbol)
        config.imagePadding = 10
        config.cornerStyle = .large
        config.contentInsets = NSDirectionalEdgeInsets(top: 16, leading: 16, bottom: 16, trailing: 16)
        button.configuration = config
        button.titleLabel?.adjustsFontForContentSizeCategory = true
        button.titleLabel?.numberOfLines = 0
        button.heightAnchor.constraint(greaterThanOrEqualToConstant: 54).isActive = true
    }

    private func label(_ text: String, style: UIFont.TextStyle = .subheadline) -> UILabel {
        let label = UILabel()
        label.text = text
        label.numberOfLines = 0
        label.font = .preferredFont(forTextStyle: style)
        label.adjustsFontForContentSizeCategory = true
        label.textColor = style == .headline ? .label : .secondaryLabel
        return label
    }

    private func card(_ views: [UIView]) -> UIView {
        let stack = UIStackView(arrangedSubviews: views)
        stack.axis = .vertical
        stack.spacing = 14
        stack.isLayoutMarginsRelativeArrangement = true
        stack.directionalLayoutMargins = NSDirectionalEdgeInsets(top: 22, leading: 20, bottom: 22, trailing: 20)
        stack.backgroundColor = .secondarySystemGroupedBackground
        stack.layer.cornerRadius = 24
        stack.layer.cornerCurve = .continuous
        return stack
    }
}
