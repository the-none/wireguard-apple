// SPDX-License-Identifier: MIT

import UIKit

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var mainVC: MainViewController?
    private var launchOptions: UIScene.ConnectionOptions?
    private var isLaunchedForSpecificAction = false
    private static let restorationActivityType = "com.wireguard.ios.tunnel-detail"

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }

        launchOptions = connectionOptions
        isLaunchedForSpecificAction = !connectionOptions.urlContexts.isEmpty || connectionOptions.shortcutItem != nil

        let mainVC = MainViewController()
        self.mainVC = mainVC
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = mainVC
        self.window = window
        window.makeKeyAndVisible()
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        mainVC?.refreshTunnelConnectionStatuses()

        // Cold-start actions arrive in connection options, not the warm callbacks.
        // Consume them once, after the window is ready for presentation.
        guard let options = launchOptions else { return }
        launchOptions = nil
        if !options.urlContexts.isEmpty {
            mainVC?.importFromDisposableFiles(urls: options.urlContexts.map { $0.url })
        } else if let shortcutItem = options.shortcutItem {
            _ = performAction(for: shortcutItem)
        }
    }

    func sceneWillResignActive(_ scene: UIScene) {
        guard let allTunnelNames = mainVC?.allTunnelNames() else { return }
        UIApplication.shared.shortcutItems = QuickActionItem.createItems(allTunnelNames: allTunnelNames)
    }

    func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
        mainVC?.importFromDisposableFiles(urls: URLContexts.map { $0.url })
    }

    func windowScene(_ windowScene: UIWindowScene, performActionFor shortcutItem: UIApplicationShortcutItem, completionHandler: @escaping (Bool) -> Void) {
        completionHandler(performAction(for: shortcutItem))
    }

    private func performAction(for shortcutItem: UIApplicationShortcutItem) -> Bool {
        guard shortcutItem.type == QuickActionItem.type, let mainVC = mainVC else { return false }
        mainVC.showTunnelDetailForTunnel(named: shortcutItem.localizedTitle, animated: false, shouldToggleStatus: true)
        return true
    }

    func stateRestorationActivity(for scene: UIScene) -> NSUserActivity? {
        guard let tunnelName = mainVC?.restorableTunnelName else { return nil }
        let activity = NSUserActivity(activityType: Self.restorationActivityType)
        activity.userInfo = ["tunnelName": tunnelName]
        activity.isEligibleForHandoff = false
        return activity
    }

    func scene(_ scene: UIScene, restoreInteractionStateWith stateRestorationActivity: NSUserActivity) {
        guard !isLaunchedForSpecificAction,
              stateRestorationActivity.activityType == Self.restorationActivityType,
              let tunnelName = stateRestorationActivity.userInfo?["tunnelName"] as? String else { return }
        mainVC?.showTunnelDetailForTunnel(named: tunnelName, animated: false, shouldToggleStatus: false)
    }
}
