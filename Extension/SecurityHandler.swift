import MailKit
import os
import SigilCore

final class SecurityHandler: NSObject, MEMessageSecurityHandler {
    private let logger = Logger(subsystem: "org.fuchss.sigil", category: "security")

    // MARK: MEMessageEncoder

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext,
                           completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        let recipients = message.toAddresses + message.ccAddresses + message.bccAddresses
        var addressesBySpec: [String: MEEmailAddress] = [:]
        for address in recipients { addressesBySpec[SecurityHandler.spec(address)] = address }
        let from = SecurityHandler.spec(message.fromAddress)
        Task { [logger] in
            do {
                let status = try await HelperClient.shared.encodingStatus(from: from, recipients: recipients.map(SecurityHandler.spec))
                logger.info("""
                    encoding status: canSign \(status.canSign), canEncrypt \(status.canEncrypt), \
                    \(status.missingRecipients.count) missing, \(status.unverifiedRecipients.count) unverified, \
                    \(status.ambiguousRecipients.count) ambiguous
                    """)
                completionHandler(MEOutgoingMessageEncodingStatus(
                    canSign: status.canSign,
                    canEncrypt: status.canEncrypt && status.missingRecipients.isEmpty,
                    securityError: nil,
                    addressesFailingEncryption: status.missingRecipients.compactMap { addressesBySpec[$0] }))
            } catch {
                logger.error("encoding status failed: \(error.localizedDescription, privacy: .private)")
                completionHandler(MEOutgoingMessageEncodingStatus(
                    canSign: false, canEncrypt: false,
                    securityError: SecurityHandler.helperUnavailableError(error),
                    addressesFailingEncryption: []))
            }
        }
    }

    /// The address as handed to the helper (it extracts the email itself).
    private static func spec(_ address: MEEmailAddress) -> String {
        address.addressString ?? address.rawString
    }

    private static func helperUnavailableError(_ underlying: Error) -> NSError {
        NSError(domain: "org.fuchss.sigil", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "The Sigil helper isn't running. Open the Sigil app and register the helper.",
            NSLocalizedFailureReasonErrorKey: underlying.localizedDescription,
            NSUnderlyingErrorKey: underlying,
        ])
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext,
                completionHandler: @escaping (MEMessageEncodingResult) -> Void) {
        let sign = composeContext.shouldSign
        let encrypt = composeContext.shouldEncrypt
        logger.info("encode: sign \(sign), encrypt \(encrypt), state \(message.state.rawValue)")
        guard sign || encrypt else {
            // Nothing to do: no encoded message and no error means "send as is" (MEMessageEncodingResult docs).
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }
        // From here on only an encoded message or an error is returned, never the unencoded input.
        let fail: (String) -> Void = { [logger] reason in
            logger.error("encode failed: \(reason, privacy: .private)")
            let error = SecurityHandler.encodingError(reason, encrypting: encrypt)
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: sign ? error : nil,
                                                      encryptionError: encrypt ? error : nil))
        }
        guard let data = message.rawData, !data.isEmpty else {
            fail("Mail did not hand over the message content.")
            return
        }
        SecurityHandler.logShape(of: data, classification: .none, operation: "encode")

        let from = SecurityHandler.spec(message.fromAddress)
        let recipients = (message.toAddresses + message.ccAddresses).map(SecurityHandler.spec)
        let hidden = message.bccAddresses.map(SecurityHandler.spec)
        Task { [logger] in
            let started = Date()
            do {
                let encoded = try await HelperClient.shared.encodeForMail(
                    message: data, sign: sign, encrypt: encrypt, from: from, recipients: recipients, hiddenRecipients: hidden)
                let seconds = Date().timeIntervalSince(started)
                logger.info("""
                    encoded in \(seconds, format: .fixed(precision: 2)) s: \(data.count) -> \(encoded.count) bytes, \
                    \(recipients.count) recipients, \(hidden.count) hidden, LF output \(LineEndings.usesBareLF(encoded))
                    """)
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: MEEncodedOutgoingMessage(rawData: encoded, isSigned: sign, isEncrypted: encrypt),
                    signingError: nil, encryptionError: nil))
            } catch {
                fail(error.localizedDescription)
            }
        }
    }

    private static func encodingError(_ reason: String, encrypting: Bool) -> NSError {
        let action = encrypting ? "encrypt" : "sign"
        return NSError(domain: MEMessageSecurityError.errorDomain, code: MEMessageSecurityError.Code.encodingError.rawValue,
                       userInfo: [NSLocalizedDescriptionKey: "Sigil could not \(action) the message: \(reason)",
                                  NSLocalizedFailureReasonErrorKey: reason])
    }

    // MARK: MEMessageDecoder

    /// Budget for the synchronous, non-interactive decode while Mail waits to show the message. It never waits for
    /// a person (pinentry is disabled), so it only covers launchd starting the helper and gpg-agent cold
    /// (~0.5 s), gpg decrypting/verifying, and key lookups for the signers; several MB of attachments take well
    /// under a second. 8 s leaves room for a slow first start or a smartcard while keeping a hung helper from
    /// freezing the message view for long; on timeout the message shows a "Retry" banner.
    static let decodeTimeout: TimeInterval = 8
    /// The interactive decrypt waits for the passphrase entry; the helper kills gpg after 120 s.
    static let interactiveDecodeTimeout: TimeInterval = 150

    /// Ciphertext of messages showing the "Decrypt" banner: `primaryActionClicked` only gets the context
    /// (hash), not the message bytes. In memory only.
    private let pendingMessages = MessageByteCache(capacity: 5)

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        // Cheap local check, so ordinary mail never goes to the helper.
        let classification = PGPDetector.classify(messageData: data)
        SecurityHandler.logShape(of: data, classification: classification)
        guard classification != .none else { return nil }

        // Message-list previews arrive truncated; gpg cannot handle that, so show a local preview instead.
        if !PGPDetector.isComplete(messageData: data) {
            logger.info("incomplete message (\(data.count) bytes), returning preview")
            let preview = DecodePresentation.preview(original: data, classification: classification)
            return SecurityHandler.decodedMessage(preview, lineEndingsLike: data)
        }

        let started = Date()
        let presentation: DecodePresentation
        do {
            guard let outcome = try HelperClient.shared.decodeSync(message: data, interactive: false,
                                                                   timeout: SecurityHandler.decodeTimeout) else {
                return nil
            }
            presentation = DecodePresentation.make(outcome: outcome, original: data)
            let signerStatuses = outcome.signers.map(\.status.rawValue).joined(separator: ",")
            let seconds = Date().timeIntervalSince(started)
            logger.info("""
                decoded \(classification.rawValue, privacy: .public) in \(seconds, format: .fixed(precision: 2)) s: \
                encrypted \(outcome.encrypted), signers [\(signerStatuses, privacy: .public)], \
                partial \(outcome.partial), needsPassphrase \(outcome.needsPassphrase), \
                mixed \(outcome.mixedEncryption), error \(outcome.error ?? "none", privacy: .private)
                """)
        } catch {
            logger.error("decode failed: \(error.localizedDescription, privacy: .private)")
            presentation = DecodePresentation.helperFailure(original: data, title: SecurityHandler.bannerTitle(for: error))
        }

        if let context = presentation.context.flatMap(MessageContext.decode),
           context.action == .decrypt || context.action == .decryptMixed {
            pendingMessages.insert(data, hash: context.messageHash)
        }
        return SecurityHandler.decodedMessage(presentation, lineEndingsLike: data)
    }

    /// Mail hands messages over with LF line endings; hand them back the same way (our MIME code emits CRLF).
    private static func matchingLineEndings(_ output: Data, like input: Data) -> Data {
        LineEndings.usesBareLF(input) ? LineEndings.toLF(output) : output
    }

    /// Diagnostics: structure of what Mail hands us (size, line endings, top-level Content-Type). Never content.
    private static func logShape(of data: Data, classification: MessageClassification, operation: String = "decode") {
        let bytes = [UInt8](data.prefix(64 * 1024))
        var crlf = 0, lf = 0
        for i in bytes.indices where bytes[i] == 0x0A {
            if i > 0 && bytes[i - 1] == 0x0D { crlf += 1 } else { lf += 1 }
        }
        let head = String(decoding: bytes.prefix(8 * 1024), as: UTF8.self)
        let contentType = head.components(separatedBy: .newlines)
            .first { $0.lowercased().hasPrefix("content-type:") } ?? "(none)"
        let headerNames = head.components(separatedBy: "\n").prefix { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .compactMap { line -> String? in
                guard let c = line.firstIndex(of: ":"), !line.hasPrefix(" "), !line.hasPrefix("\t") else { return nil }
                return String(line[..<c])
            }.joined(separator: ",")
        Logger(subsystem: "org.fuchss.sigil", category: "security").info("""
            \(operation, privacy: .public) called: \(data.count) bytes, crlf \(crlf), lf \(lf), class \(classification.rawValue, privacy: .public), \
            \(contentType.prefix(120), privacy: .private), headers [\(headerNames.prefix(300), privacy: .public)]
            """)
    }

    private static func bannerTitle(for error: Error) -> String {
        switch error as? HelperClient.ClientError {
        case .timedOut: return "Sigil helper did not answer in time."
        case let .helper(message): return "Sigil could not check this message: \(message)"
        default: return "Sigil helper not reachable."
        }
    }

    /// Translates the MailKit-free presentation into MailKit objects.
    private static func decodedMessage(_ p: DecodePresentation, lineEndingsLike input: Data) -> MEDecodedMessage {
        let signers = p.signers.map { signer in
            MEMessageSigner(emailAddresses: signer.emailAddresses.map { MEEmailAddress(rawString: $0) },
                            signatureLabel: signer.label, context: signer.context)
        }
        // No signingError/encryptionError: Mail never shows their text, but builds a CertificateBanner for them that
        // crashes Mail (CertificateBanner.swift:53 "without a valid error") when such a message is deleted.
        // Sigil's own banner and warning box report the problem instead.
        let security = MEMessageSecurityInformation(
            signers: signers, isEncrypted: p.isEncrypted, signingError: nil, encryptionError: nil,
            shouldBlockRemoteContent: p.blocksRemoteContent,
            localizedRemoteContentBlockingReason: p.remoteContentBlockingReason)
        let banner = p.banner.map {
            MEDecodedMessageBanner(title: $0.title, primaryActionTitle: $0.actionTitle, dismissable: $0.dismissable)
        }
        let data = matchingLineEndings(p.rawData, like: input)
        Logger(subsystem: "org.fuchss.sigil", category: "security").info("""
            returning \(data.count) bytes (was \(p.rawData.count)), encrypted \(p.isEncrypted), \
            signers \(signers.count), banner \(banner != nil)
            """)
        return MEDecodedMessage(data: data, securityInformation: security, context: p.context, banner: banner)
    }

    // MARK: MEMessageSecurityHandler

    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        let details = messageSigners.compactMap { SignerContext.decode($0.context) }.map { SignerDetails(context: $0) }
        return SignerDetailsViewController(details: details)
    }

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        guard let messageContext = MessageContext.decode(context) else { return nil }
        switch messageContext.action {
        case .partialInfo: return SecurityHandler.partialInfoViewController()
        case .info: return SecurityHandler.infoViewController(messageContext)
        default: return nil
        }
    }

    private static func infoViewController(_ context: MessageContext) -> MEExtensionViewController {
        MessageInfoViewController(heading: context.heading ?? "Sigil", message: context.detail ?? "")
    }

    private static func partialInfoViewController() -> MEExtensionViewController {
        MessageInfoViewController(
            heading: "Only part of this message is encrypted.",
            message: "The message mixes encrypted and unencrypted parts. Only the decrypted part is confidential, "
                + "and text outside it may have been added by someone else, so Sigil does not show the message as encrypted.")
    }

    func primaryActionClicked(forMessageContext context: Data,
                              completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        guard let messageContext = MessageContext.decode(context) else {
            completionHandler(nil)
            return
        }
        switch messageContext.action {
        case .partialInfo:
            completionHandler(SecurityHandler.partialInfoViewController())
        case .info:
            completionHandler(SecurityHandler.infoViewController(messageContext))
        case .retry:
            logger.info("retry requested")
            reloadVisibleMessages()
            completionHandler(nil)
        case .decrypt:
            guard let message = pendingMessages.data(forHash: messageContext.messageHash) else {
                // The extension was restarted since the message was shown. Showing it again caches it.
                logger.info("decrypt requested, message no longer cached; reloading")
                reloadVisibleMessages()
                completionHandler(MessageInfoViewController(
                    heading: "Please click Decrypt again.",
                    message: "Sigil had to reload the message before it can decrypt it."))
                return
            }
            decryptInteractively(message, hash: messageContext.messageHash, completionHandler: completionHandler)
        case .decryptMixed:
            guard let message = pendingMessages.data(forHash: messageContext.messageHash) else {
                logger.info("decrypt anyway requested, message no longer cached; reloading")
                reloadVisibleMessages()
                completionHandler(MessageInfoViewController(
                    heading: "Please click Decrypt anyway again.",
                    message: "Sigil had to reload the message before it can decrypt it."))
                return
            }
            decryptMixed(message, completionHandler: completionHandler)
        }
    }

    /// "Decrypt anyway" for encrypted parts mixed with other content: the plaintext is shown as plain text in Sigil's
    /// own view only. It never goes back to Mail as message content (no HTML or remote content can carry it out, and a
    /// reply or forward cannot quote it); the message itself stays as it is, remote content blocked.
    private func decryptMixed(_ message: Data, completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        logger.info("decrypt anyway requested")
        Task { @MainActor [logger] in
            do {
                let outcome = try await HelperClient.shared.decode(message: message, interactive: true, allowMixed: true,
                                                                   timeout: SecurityHandler.interactiveDecodeTimeout)
                if let decoded = outcome?.message {
                    completionHandler(PlaintextViewController(
                        heading: "Decrypted parts of this message",
                        note: "Shown here only. The message in Mail stays encrypted; parts outside the encrypted "
                            + "content may have been added by someone else.",
                        text: MixedDecryption.readableText(of: decoded)))
                } else {
                    logger.error("decrypt anyway failed: \(outcome?.error ?? "not a PGP message", privacy: .private)")
                    completionHandler(MessageInfoViewController(
                        heading: "The message was not decrypted.",
                        message: outcome?.error ?? "Sigil found nothing to decrypt."))
                }
            } catch {
                logger.error("decrypt anyway: helper failed: \(error.localizedDescription, privacy: .private)")
                completionHandler(MessageInfoViewController(heading: "Sigil helper not reachable.",
                                                            message: error.localizedDescription))
            }
        }
    }

    /// Decrypts with pinentry allowed, so gpg-agent caches the passphrase; the reload then decodes the message
    /// non-interactively from the cache. The plaintext of this call is dropped.
    private func decryptInteractively(_ message: Data, hash: String,
                                      completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        logger.info("interactive decrypt requested")
        Task { @MainActor [logger, pendingMessages] in
            do {
                let outcome = try await HelperClient.shared.decode(message: message, interactive: true,
                                                                   timeout: SecurityHandler.interactiveDecodeTimeout)
                if let outcome, outcome.message != nil {
                    logger.info("interactive decrypt succeeded")
                    pendingMessages.remove(hash: hash)
                    self.reloadVisibleMessages()
                    completionHandler(nil)
                } else if outcome?.needsPassphrase == true {
                    logger.info("interactive decrypt: no passphrase (cancelled or wrong)")
                    completionHandler(MessageInfoViewController(
                        heading: "The message was not decrypted.",
                        message: "The passphrase entry was cancelled or the passphrase was wrong. Click Decrypt to try again."))
                } else {
                    logger.error("interactive decrypt failed: \(outcome?.error ?? "not a PGP message", privacy: .private)")
                    pendingMessages.remove(hash: hash)
                    self.reloadVisibleMessages()
                    completionHandler(nil)
                }
            } catch {
                logger.error("interactive decrypt: helper failed: \(error.localizedDescription, privacy: .private)")
                completionHandler(MessageInfoViewController(heading: "Sigil helper not reachable.",
                                                            message: error.localizedDescription))
            }
        }
    }

    private func reloadVisibleMessages() {
        MEExtensionManager.reloadVisibleMessages { [logger] error in
            if let error { logger.error("reloading messages failed: \(error.localizedDescription, privacy: .private)") }
        }
    }
}
