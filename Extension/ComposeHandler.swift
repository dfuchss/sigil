import MailKit
import os
import SigilCore

/// One compose window. Annotates recipients whose key is not verified (or who have several unverified keys), and
/// blocks sending an encrypted message when a recipient has no usable key or several unverified ones. Recipients
/// without a key are not annotated: Mail itself already disables the encrypt button then.
/// `session.composeContext.shouldEncrypt` is Mail's encrypt toggle; `encode` refuses on its own as well (it never
/// sends plaintext when encryption was requested, and never guesses between keys).
final class ComposeHandler: NSObject, MEComposeSessionHandler {
    private let logger = Logger(subsystem: "org.fuchss.sigil", category: "compose")

    func mailComposeSessionDidBegin(_ session: MEComposeSession) {
        logger.info("compose session began")
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        logger.info("compose session ended")
    }

    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        MessageInfoViewController(
            heading: "Sigil",
            message: "Use the lock and checkmark buttons in the message header to encrypt and sign with OpenPGP. "
                + "Encryption needs an OpenPGP key for every recipient.")
    }

    static let unverifiedNote = "Key not verified – compare the fingerprint"

    /// Ambiguous recipients get an error annotation (sending encrypted will be refused), recipients whose chosen key is
    /// not fully or ultimately valid a warning; nobody else is annotated.
    func annotateAddressesForSession(_ session: MEComposeSession,
                                     completion: @escaping ([MEEmailAddress: MEAddressAnnotation]) -> Void) {
        let message = session.mailMessage
        let addresses = message.toAddresses + message.ccAddresses + message.bccAddresses
        guard !addresses.isEmpty else { return completion([:]) }
        var bySpec: [String: [MEEmailAddress]] = [:]
        for address in addresses { bySpec[ComposeHandler.spec(address), default: []].append(address) }
        let from = ComposeHandler.spec(message.fromAddress)
        Task { [logger] in
            do {
                let status = try await HelperClient.shared.encodingStatus(from: from, recipients: Array(bySpec.keys))
                var annotations: [MEEmailAddress: MEAddressAnnotation] = [:]
                for spec in status.unverifiedRecipients {
                    for address in bySpec[spec] ?? [] {
                        annotations[address] = .warning(withLocalizedDescription: ComposeHandler.unverifiedNote)
                    }
                }
                for spec in status.ambiguousRecipients {
                    let email = EmailAddress.extract(spec)
                    for address in bySpec[spec] ?? [] {
                        annotations[address] = .error(withLocalizedDescription:
                            "Several unverified keys – choose one under Public Keys > Prefer for \(email) in the Sigil app")
                    }
                }
                logger.info("annotated \(annotations.count) of \(addresses.count) recipients")
                completion(annotations)
            } catch {
                logger.error("annotating recipients failed: \(error.localizedDescription, privacy: .private)")
                completion([:])
            }
        }
    }

    func allowMessageSendForSession(_ session: MEComposeSession, completion: @escaping (Error?) -> Void) {
        let context = session.composeContext
        logger.info("send requested: shouldEncrypt \(context.shouldEncrypt), shouldSign \(context.shouldSign)")
        guard context.shouldEncrypt else { return completion(nil) }
        let message = session.mailMessage
        let recipients = (message.toAddresses + message.ccAddresses + message.bccAddresses).map(ComposeHandler.spec)
        let from = ComposeHandler.spec(message.fromAddress)
        Task { [logger] in
            do {
                let status = try await HelperClient.shared.encodingStatus(from: from, recipients: recipients)
                guard status.missingRecipients.isEmpty else {
                    let names = status.missingRecipients.joined(separator: ", ")
                    logger.info("send blocked: \(status.missingRecipients.count) recipients without key")
                    return completion(ComposeHandler.sendError(
                        "No OpenPGP key for \(names). Remove these recipients or turn off encryption.", code: .invalidRecipients))
                }
                guard status.ambiguousRecipients.isEmpty else {
                    logger.info("send blocked: \(status.ambiguousRecipients.count) recipients with several unverified keys")
                    let text = GPGError.ambiguousRecipients(status.ambiguousRecipients.map(EmailAddress.extract))
                        .errorDescription ?? ""
                    return completion(ComposeHandler.sendError(text, code: .invalidRecipients))
                }
                completion(nil)
            } catch {
                logger.error("send check failed: \(error.localizedDescription, privacy: .private)")
                completion(ComposeHandler.sendError(
                    "Sigil cannot encrypt the message: \(error.localizedDescription)", code: .invalidBody))
            }
        }
    }

    private static func spec(_ address: MEEmailAddress) -> String {
        address.addressString ?? address.rawString
    }

    private static func sendError(_ description: String, code: MEComposeSessionError.Code) -> NSError {
        NSError(domain: MEComposeSessionError.errorDomain, code: code.rawValue,
                userInfo: [NSLocalizedDescriptionKey: description])
    }
}
