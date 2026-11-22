import Foundation
import os
import SigilCore

private let logger = Logger(subsystem: "org.fuchss.sigil", category: "helper")

/// Accepts connections from Sigil and its Mail extension only, and exports a `GPGService` to them. Each connection's
/// service knows which of the two is calling (from the code signature behind the connection's audit token), and the
/// extension only gets the methods `ServiceAuthorization` allows it.
final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    /// Code signing requirement every client must satisfy (checked by XPC for each message).
    let clientRequirement: String
    let prefix: String
    let appGroupID: String
    /// Shared by all connections, so repeated decodes of a message count once whichever client sends them.
    let missingKeys: MissingKeyRecorder?
    let preferredKeys: PreferredKeyStore?
    /// The helper's own settings (gpg path), outside the App Group container.
    let settings: HelperSettings

    init(teamID: String, prefix: String) {
        clientRequirement = SigilXPC.clientRequirement(teamID: teamID, prefix: prefix)
        self.prefix = prefix
        appGroupID = SigilXPC.appGroupID(teamID: teamID, prefix: prefix)
        missingKeys = MissingKeyStore.inAppGroup(appGroupID).map { MissingKeyRecorder(store: $0) }
        preferredKeys = PreferredKeyStore.inAppGroup(appGroupID)
        settings = HelperSettings.standard(prefix: prefix)
        if missingKeys == nil { logger.error("no App Group container: the missing-keys list is disabled") }
        super.init()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let pid = newConnection.processIdentifier
        guard let caller = callerRole(of: newConnection) else {
            logger.error("rejected connection from pid \(pid): not the Sigil app or its Mail extension")
            return false
        }
        newConnection.setCodeSigningRequirement(clientRequirement)
        newConnection.exportedInterface = SigilXPC.makeInterface()
        let service = makeService(caller: caller)
        newConnection.exportedObject = service
        // A client that gives up (timeout) drops the connection: stop its gpg runs.
        newConnection.invalidationHandler = {
            service.cancelAll()
            logger.debug("connection from pid \(pid) invalidated")
        }
        newConnection.resume()
        logger.info("connection from pid \(pid), caller \(caller.rawValue, privacy: .public)")
        return true
    }

    /// The caller role from the connection's audit token (not the pid, which can be recycled): the signing identifier
    /// of a valid signature that satisfies the client requirement.
    private func callerRole(of connection: NSXPCConnection) -> XPCCaller? {
        // The audit token is not public API on NSXPCConnection; it is available through KVC.
        guard let value = connection.value(forKey: "auditToken") as? NSValue else { return nil }
        var token = audit_token_t()
        value.getValue(&token, size: MemoryLayout<audit_token_t>.size)
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        guard let identifier = SigilXPC.signingIdentifier(auditToken: tokenData, requirement: clientRequirement) else {
            return nil
        }
        return XPCCaller.from(signingIdentifier: identifier, prefix: prefix)
    }

    /// A fresh service per connection, so a changed gpg path applies once a client reconnects. The gpg path comes
    /// only from the helper's own settings (an old App Group `gpgPath` value is ignored).
    private func makeService(caller: XPCCaller) -> GPGService {
        let configuredPath = settings.gpgPath()
        var gpgURL: URL?
        var firstProblem: Error?
        for candidate in [configuredPath].compactMap({ $0 }) + GPGRunner.defaultCandidates {
            do {
                gpgURL = try GPGPathValidator.validate(candidate)
                break
            } catch {
                guard FileManager.default.fileExists(atPath: candidate) else { continue }
                logger.error("gpg candidate rejected: \(error.localizedDescription, privacy: .private)")
                if firstProblem == nil { firstProblem = error }
            }
        }
        var runnerError: GPGError?
        if let gpgURL {
            logger.info("using gpg at \(gpgURL.path, privacy: .public)")
        } else {
            switch firstProblem {
            case let error as GPGError: runnerError = error
            case let error as GPGPathValidator.Rejected: runnerError = .launchFailed(error.message)
            default: runnerError = .gpgNotFound
            }
            logger.error("no usable gpg found")
        }
        return GPGService(runner: gpgURL.map { GPGRunner(gpgPath: $0, timeout: 120) }, missingKeys: missingKeys,
                          preferredKeys: preferredKeys, caller: caller, settings: settings, runnerError: runnerError)
    }
}
