import UIKit

final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        do {
            let store = try SessionStore()
            window.rootViewController = UINavigationController(rootViewController: DiagnosticViewController(store: store))
        } catch {
            let controller = UIViewController()
            controller.view.backgroundColor = .systemBackground
            let label = UILabel()
            label.numberOfLines = 0
            label.text = "无法初始化持久化日志，诊断已禁用：\n\(error.localizedDescription)"
            label.translatesAutoresizingMaskIntoConstraints = false
            controller.view.addSubview(label)
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: controller.view.leadingAnchor, constant: 24),
                label.trailingAnchor.constraint(equalTo: controller.view.trailingAnchor, constant: -24),
                label.centerYAnchor.constraint(equalTo: controller.view.centerYAnchor)
            ])
            window.rootViewController = controller
        }
        window.makeKeyAndVisible()
        self.window = window
        return true
    }
}
