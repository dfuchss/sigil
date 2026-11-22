import MailKit
import os

final class MailExtension: NSObject, MEExtension {
    private let securityHandler = SecurityHandler()
    private let logger = Logger(subsystem: "org.fuchss.sigil", category: "extension")

    override init() {
        super.init()
        Task { [logger] in
            do {
                let version = try await HelperClient.shared.ping()
                logger.info("extension started, helper ping: \(version, privacy: .public)")
            } catch {
                logger.error("extension started, helper ping failed: \(error.localizedDescription, privacy: .private)")
            }
        }
    }

    func handlerForMessageSecurity() -> MEMessageSecurityHandler {
        securityHandler
    }

    func handler(for session: MEComposeSession) -> MEComposeSessionHandler {
        ComposeHandler()
    }
}
