import Foundation
import os
import ServiceManagement
import SigilCore

/// The SigilHelper LaunchAgent, registered through SMAppService.
enum HelperAgent {
    /// The plist name comes from Info.plist (`<prefix>.helper.plist`), so Debug and Release use different agents.
    static let service = SMAppService.agent(plistName: SigilXPC.helperPlistName ?? "org.fuchss.sigil.helper.plist")
    private static let logger = Logger(subsystem: "org.fuchss.sigil", category: "app")

    /// The App Group shared with the helper and the Mail extension (`<TEAM>.<prefix>`), from Info.plist.
    static var appGroupID: String? { SigilXPC.appGroup }

    static var sharedDefaults: UserDefaults? { appGroupID.flatMap { UserDefaults(suiteName: $0) } }

    /// The gpg path used to live in the App Group defaults, where the Mail extension could change it. The helper
    /// ignores that value now; remove it.
    static func removeLegacyGPGPath() {
        sharedDefaults?.removeObject(forKey: "gpgPath")
    }

    static func describe(_ status: SMAppService.Status) -> String {
        switch status {
        case .notRegistered: return "Not registered"
        case .enabled: return "Enabled"
        case .requiresApproval: return "Requires approval in System Settings > General > Login Items & Extensions"
        case .notFound: return "Not found"
        @unknown default: return "Unknown"
        }
    }

    static func unregisterAndLog() {
        let semaphore = DispatchSemaphore(value: 0)
        service.unregister { error in
            if let error {
                logger.error("helper unregister failed: \(error.localizedDescription, privacy: .private)")
            } else {
                logger.info("helper unregistered")
            }
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 10)
    }

    static func registerAndLog() {
        do {
            try service.register()
            logger.info("helper registered, status: \(describe(service.status), privacy: .public)")
        } catch {
            logger.error("helper registration failed: \(error.localizedDescription, privacy: .private); status: \(describe(service.status), privacy: .public)")
        }
    }
}
