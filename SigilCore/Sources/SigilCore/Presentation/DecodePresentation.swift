import CryptoKit
import Foundation

/// What the Mail extension shows for a received message, derived from a `DecodeOutcome` without MailKit.
/// The extension only translates this value into MailKit objects.
public struct DecodePresentation: Equatable, Sendable {
    /// The message Mail displays: the decoded message, or the original (never partial plaintext).
    public var rawData: Data
    /// Shown as encrypted only when the whole message was encrypted and decrypted.
    public var isEncrypted: Bool
    public var signers: [SignerPresentation]
    public var signingError: String?
    public var encryptionError: String?
    public var blocksRemoteContent: Bool
    public var remoteContentBlockingReason: String?
    public var banner: BannerPresentation?
    /// JSON `MessageContext` for the banner action; nil without a banner.
    public var context: Data?

    public static let remoteContentReason =
        "Sigil blocks remote content in decrypted messages, so that loading it cannot leak the plaintext (EFAIL)."

    /// Maps a decode outcome of the helper. `original` is the message as Mail handed it to the extension.
    /// With a red or yellow `MessageMark` the displayed body gets a warning box in front (see `WarningBox`).
    /// The box is only an extra: every case that gets one also has a banner and no `MEMessageSigner` (Mail's own
    /// signer state is the authoritative signal; a forged box in an attacker's HTML cannot set those).
    public static func make(outcome: DecodeOutcome, original: Data) -> DecodePresentation {
        let sender = RFC822Message(data: original).header("From").flatMap { EmailAddress.parse($0).email }
        var p = makeUnmarked(outcome: outcome, original: original, sender: sender)
        let mark = MessageMark.of(outcome)
        guard mark != .none, !outcome.needsPassphrase, !outcome.mixedEncryption,
              !(outcome.message == nil && outcome.encrypted) else { return p }
        let box = WarningBox.make(mark: mark, headline: p.banner?.title ?? "", outcome: outcome, signingError: p.signingError,
                                  sender: sender)
        p.rawData = box.prepended(to: p.rawData)
        return p
    }

    public static let mixedEncryptionTitle =
        "This message contains encrypted parts mixed with other content. Decrypting it could leak the plaintext."

    private static func makeUnmarked(outcome: DecodeOutcome, original: Data, sender: String?) -> DecodePresentation {
        let hash = MessageContext.hash(of: original)
        var p = DecodePresentation(rawData: original, isEncrypted: false, signers: [], signingError: nil,
                                   encryptionError: nil, blocksRemoteContent: false, remoteContentBlockingReason: nil,
                                   banner: nil, context: nil)
        if outcome.mixedEncryption {
            // Nothing was decrypted; the original is shown with remote content blocked. "Decrypt anyway" shows the
            // plaintext in Sigil's own view, never inside this message.
            p.blocksRemoteContent = true
            p.remoteContentBlockingReason = remoteContentReason
            p.set(banner: BannerPresentation(title: mixedEncryptionTitle, actionTitle: "Decrypt anyway", dismissable: true),
                  action: .decryptMixed, hash: hash)
            return p
        }
        if outcome.encrypted {
            p.blocksRemoteContent = true
            p.remoteContentBlockingReason = remoteContentReason
        }

        if outcome.needsPassphrase {
            p.isEncrypted = true
            p.set(banner: BannerPresentation(title: "This message is encrypted.", actionTitle: "Decrypt", dismissable: false),
                  action: .decrypt, hash: hash)
            return p
        }

        guard let decoded = outcome.message else {
            let reason = outcome.error ?? "Unknown error."
            if outcome.encrypted {
                p.isEncrypted = true
                p.encryptionError = "This message could not be decrypted. \(reason)"
                p.rawData = failureMessage(original: original, reason: reason)
                p.set(info: "Sigil could not decrypt this message: \(shortReason(reason))", detail: p.encryptionError ?? "",
                      dismissable: false, hash: hash)
            } else {
                p.signingError = "This message could not be checked. \(reason)"
                p.set(info: "Sigil could not check this message: \(shortReason(reason))", detail: p.signingError ?? "",
                      dismissable: false, hash: hash)
            }
            return p
        }

        p.rawData = decoded
        p.isEncrypted = outcome.encrypted && !outcome.partial
        // Mail shows its normal "signed" badge for every signer and ignores signingError, so only valid
        // signatures over the whole message become signers; every other case is reported by the banner.
        p.signers = outcome.partial ? [] : outcome.signers
            .filter { $0.status == .good && SignerPresentation.problem(of: $0, decodeError: outcome.error, sender: sender) == nil }
            .map { SignerPresentation(signer: $0, partial: false) }
        let problems = outcome.signers.compactMap {
            SignerPresentation.problem(of: $0, decodeError: outcome.error, sender: sender)
        }
        if !problems.isEmpty {
            p.signingError = problems.joined(separator: "\n")
        } else if outcome.partial && outcome.signed {
            p.signingError = "Only part of this message is signed. Text outside the signed part may have been added by someone else."
        }
        if let signingError = p.signingError {
            let kinds = outcome.signers.compactMap { SignatureProblem.of($0) }
            let worst = kinds.max() ?? .partial
            var title = worst.bannerTitle
            if worst == .wrongSender, let signer = outcome.signers.first(where: { SignatureProblem.of($0) == .wrongSender }),
               let text = SignerPresentation.problem(of: signer, decodeError: outcome.error, sender: sender) {
                title = text
            }
            p.set(info: title, detail: signingError, dismissable: worst.dismissable, hash: hash)
        } else if outcome.partial && outcome.encrypted {
            p.set(banner: BannerPresentation(title: "Only part of this message is encrypted.", actionTitle: "Details",
                                             dismissable: true),
                  action: .partialInfo, hash: hash)
        }
        return p
    }

    /// What to show for a truncated message (Mail's message-list previews). No helper call, nothing cached:
    /// encrypted messages get a placeholder, signed ones their readable first part, otherwise the original.
    public static func preview(original: Data, classification: MessageClassification) -> DecodePresentation {
        var p = DecodePresentation(rawData: original, isEncrypted: false, signers: [], signingError: nil,
                                   encryptionError: nil, blocksRemoteContent: false, remoteContentBlockingReason: nil,
                                   banner: nil, context: nil)
        let root = MIMEEntity(data: original)
        let encrypted = classification == .pgpMimeEncrypted
            || (classification == .inline && PGPDetector.hasInlineEncryptedArmor(root))
        if encrypted {
            let headers = RFC822Message(data: original).outerHeaders
            let body = "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
                + "\u{1F512} Encrypted message\r\n"
            p.rawData = RFC822Message.combine(outerHeaders: headers, bodyEntity: Data(body.utf8))
            p.isEncrypted = true
            p.blocksRemoteContent = true
            p.remoteContentBlockingReason = remoteContentReason
        } else if classification == .pgpMimeSigned,
                  root.isPGPMIMESigned,
                  root.children.count >= 2, PGPDetector.isStructurallyTerminated(root.children[0]) {
            let headers = RFC822Message(data: original).outerHeaders
            p.rawData = RFC822Message.combine(outerHeaders: headers, bodyEntity: root.children[0].rawData)
        }
        return p
    }

    /// The helper could not be asked (not reachable, timed out, or it answered with an error).
    public static func helperFailure(original: Data, title: String) -> DecodePresentation {
        var p = DecodePresentation(rawData: original, isEncrypted: false, signers: [], signingError: nil,
                                   encryptionError: nil, blocksRemoteContent: false, remoteContentBlockingReason: nil,
                                   banner: nil, context: nil)
        p.set(banner: BannerPresentation(title: title, actionTitle: "Retry", dismissable: true),
              action: .retry, hash: MessageContext.hash(of: original))
        return p
    }

    /// "Details" banner; the context carries the heading and detail text (never message content).
    private mutating func set(info heading: String, detail: String, dismissable: Bool, hash: String) {
        banner = BannerPresentation(title: heading, actionTitle: "Details", dismissable: dismissable)
        context = try? SigilJSON.encoder().encode(MessageContext(action: .info, messageHash: hash, heading: heading, detail: detail))
    }

    /// First line of the reason, shortened for a banner title.
    static func shortReason(_ reason: String) -> String {
        let line = reason.split(whereSeparator: \.isNewline).first.map(String.init) ?? reason
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        return trimmed.count > 100 ? String(trimmed.prefix(100)) + "…" : trimmed
    }

    /// The original outer headers with only a red warning box as body; no message content, no ciphertext.
    static func failureMessage(original: Data, reason: String) -> Data {
        let box = WarningBox(mark: .red, headline: "Sigil could not decrypt this message.", lines: [reason],
                             signer: nil, fingerprint: nil)
        return RFC822Message.combine(outerHeaders: RFC822Message(data: original).outerHeaders,
                                     bodyEntity: box.entity())
    }

    private mutating func set(banner: BannerPresentation, action: MessageContext.Action, hash: String) {
        self.banner = banner
        context = try? SigilJSON.encoder().encode(MessageContext(action: action, messageHash: hash))
    }

    public init(rawData: Data, isEncrypted: Bool, signers: [SignerPresentation], signingError: String?,
                encryptionError: String?, blocksRemoteContent: Bool, remoteContentBlockingReason: String?,
                banner: BannerPresentation?, context: Data?) {
        self.rawData = rawData
        self.isEncrypted = isEncrypted
        self.signers = signers
        self.signingError = signingError
        self.encryptionError = encryptionError
        self.blocksRemoteContent = blocksRemoteContent
        self.remoteContentBlockingReason = remoteContentBlockingReason
        self.banner = banner
        self.context = context
    }
}

public struct BannerPresentation: Equatable, Sendable {
    public var title: String
    public var actionTitle: String
    public var dismissable: Bool

    public init(title: String, actionTitle: String, dismissable: Bool) {
        self.title = title
        self.actionTitle = actionTitle
        self.dismissable = dismissable
    }
}

/// Context attached to a decoded message with a banner; identifies the message by hash, never by content.
public struct MessageContext: Codable, Equatable, Sendable {
    public enum Action: String, Codable, Sendable {
        /// Decrypt interactively (passphrase not cached).
        case decrypt
        /// Decode again (helper was not reachable).
        case retry
        /// Explain a partially encrypted message.
        case partialInfo
        /// Show `heading` and `detail` (a signature or decryption problem).
        case info
        /// The user asked to decrypt encrypted parts mixed with other content: shown in Sigil's view only.
        case decryptMixed
    }

    public var action: Action
    /// SHA-256 (hex) of the original message bytes.
    public var messageHash: String
    /// Only for `.info`: the problem description, never message content.
    public var heading: String?
    public var detail: String?

    public init(action: Action, messageHash: String, heading: String? = nil, detail: String? = nil) {
        self.action = action
        self.messageHash = messageHash
        self.heading = heading
        self.detail = detail
    }

    public static func hash(of message: Data) -> String {
        SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined()
    }

    public static func decode(_ data: Data) -> MessageContext? {
        try? SigilJSON.decoder().decode(MessageContext.self, from: data)
    }
}

/// A signature problem, ordered by severity (the highest is shown in the banner).
enum SignatureProblem: Int, Comparable {
    case partial, error, unknownKey, wrongSender, distrusted, expired, revoked, bad

    static func < (lhs: SignatureProblem, rhs: SignatureProblem) -> Bool { lhs.rawValue < rhs.rawValue }

    static func of(_ signer: SignerInfo) -> SignatureProblem? {
        switch signer.status {
        case .good:
            if signer.validity == .never { return .distrusted }
            return signer.matchesSender == false ? .wrongSender : nil
        case .bad: return .bad
        case .expiredSignature, .expiredKey: return .expired
        case .revokedKey: return .revoked
        case .noPublicKey: return .unknownKey
        case .error: return .error
        }
    }

    var bannerTitle: String {
        switch self {
        case .bad: return "Invalid signature: this message was changed after it was signed."
        case .revoked: return "Signature from a revoked key."
        case .expired: return "Signature from an expired key."
        case .distrusted: return "Signed with a key you marked as not trusted."
        case .wrongSender: return "Signed by a different address."
        case .unknownKey: return "Signed with an unknown key. The signature could not be checked."
        case .error: return "The signature could not be checked."
        case .partial: return "Only part of this message is signed."
        }
    }

    var dismissable: Bool { !(self == .bad || self == .revoked || self == .partial) }
}

/// One signer as Mail shows it in the message header.
public struct SignerPresentation: Equatable, Sendable {
    public var emailAddresses: [String]
    public var label: String
    /// JSON `SignerContext`, read back by the signer details view.
    public var context: Data

    public init(signer: SignerInfo, partial: Bool) {
        emailAddresses = signer.email.map { [$0] } ?? []
        let name = SignerPresentation.name(of: signer)
        var notes: [String] = []
        let marker: String?
        switch signer.status {
        case .good where signer.validity == .never: marker = "NOT TRUSTED key"
        case .good:
            marker = nil
            notes.append(SignerPresentation.isVerified(signer.validity) ? "verified key" : "unverified key")
        case .bad: marker = "INVALID signature"
        case .expiredSignature: marker = "Expired signature"
        case .expiredKey: marker = "Expired key"
        case .revokedKey: marker = "Revoked key"
        case .noPublicKey: marker = "Unknown key"
        case .error: marker = "Signature NOT CHECKED"
        }
        if signer.matchesSender == false { notes.append("not the sender's address") }
        if partial { notes.append("only part of the message is signed") }
        let suffix = notes.isEmpty ? "" : " (\(notes.joined(separator: ", ")))"
        label = marker.map { "\($0) – \(name)\(suffix)" } ?? "\(name)\(suffix)"
        context = (try? SigilJSON.encoder().encode(SignerContext(signer: signer, partial: partial))) ?? Data()
    }

    public static func isVerified(_ validity: TrustLevel?) -> Bool {
        validity == .fully || validity == .ultimate
    }

    /// "Name <email>" or the email; without an email (unknown key, or a key without email user IDs)
    /// the key ID, after the user ID's name if there is one.
    static func name(of signer: SignerInfo) -> String {
        let parsedName = signer.userID.flatMap { EmailAddress.parse($0).name }
        switch (parsedName, signer.email) {
        case let (name?, email?): return "\(name) <\(email)>"
        case let (nil, email?): return email
        case let (name?, nil): return "\(name), key \(keyReference(signer))"
        case (nil, nil): return "key \(keyReference(signer))"
        }
    }

    static func keyReference(_ signer: SignerInfo) -> String {
        if let keyID = signer.keyID, !keyID.isEmpty { return "0x" + keyID }
        if let fpr = signer.fingerprint { return Fingerprint.grouped(fpr) }
        return "(unknown)"
    }

    /// The signing error text for a signer, nil when its signature is good, its key not distrusted, and it has a
    /// user ID for the sender (From) address.
    static func problem(of signer: SignerInfo, decodeError: String?, sender: String? = nil) -> String? {
        let who = name(of: signer)
        switch signer.status {
        case .good:
            if signer.validity == .never { return "The key of \(who) is marked as not trusted in your keyring." }
            guard signer.matchesSender == false else { return nil }
            return "Signed by a different address: \(who) is not the sender \(sender ?? "in the From header")."
        case .bad: return "The signature of \(who) is invalid: the message was changed after it was signed."
        case .expiredSignature: return "The signature of \(who) has expired."
        case .expiredKey: return "The message was signed by \(who) with a key that has expired."
        case .revokedKey: return "The message was signed by \(who) with a key that has been revoked."
        case .noPublicKey:
            return "The message is signed with an unknown key (\(keyReference(signer))). "
                + "Import the sender's public key to check the signature."
        case .error: return "The signature could not be checked. \(decodeError ?? "")".trimmingCharacters(in: .whitespaces)
        }
    }
}

/// Signer data stored in `MEMessageSigner.context`.
public struct SignerContext: Codable, Equatable, Sendable {
    public var fingerprint: String?
    public var keyID: String?
    public var email: String?
    public var userID: String?
    public var validity: TrustLevel?
    public var status: SignatureStatus
    public var created: Date?
    public var matchesSender: Bool?
    public var partial: Bool

    public init(signer: SignerInfo, partial: Bool) {
        fingerprint = signer.fingerprint
        keyID = signer.keyID
        email = signer.email
        userID = signer.userID
        validity = signer.validity
        status = signer.status
        created = signer.created
        matchesSender = signer.matchesSender
        self.partial = partial
    }

    public static func decode(_ data: Data) -> SignerContext? {
        try? SigilJSON.decoder().decode(SignerContext.self, from: data)
    }

    public var signerInfo: SignerInfo {
        SignerInfo(fingerprint: fingerprint, keyID: keyID, email: email, userID: userID, validity: validity,
                   status: status, created: created, matchesSender: matchesSender)
    }
}

/// The rows of the signer details view.
public struct SignerDetails: Equatable, Sendable {
    public struct Row: Equatable, Sendable {
        public var label: String
        public var value: String
    }

    public var title: String
    public var rows: [Row]
    /// How to verify the key; nil for verified keys.
    public var hint: String?

    public init(context: SignerContext, dateFormatter: (Date) -> String = SignerDetails.defaultDate) {
        let signer = context.signerInfo
        title = SignerPresentation.name(of: signer)
        var rows: [Row] = []
        rows.append(Row(label: "Email", value: context.email ?? "—"))
        rows.append(Row(label: "Fingerprint", value: context.fingerprint.map(Fingerprint.grouped)
                        ?? context.keyID.map { "Key ID 0x" + $0 } ?? "—"))
        rows.append(Row(label: "Key", value: SignerDetails.validityText(context)))
        rows.append(Row(label: "Signature", value: SignerDetails.statusText(context.status)
                        + (context.partial ? " (only part of the message is signed)" : "")))
        if let created = context.created { rows.append(Row(label: "Signed", value: dateFormatter(created))) }
        if let matches = context.matchesSender {
            rows.append(Row(label: "Sender", value: matches ? "Matches the From address"
                            : context.email == nil ? "Does not match the From address (the key has no email user ID)"
                            : "Does not match the From address"))
        }
        self.rows = rows

        let fpr = context.fingerprint ?? context.keyID ?? "<fingerprint>"
        if context.status == .noPublicKey {
            hint = "Sigil cannot check this signature because the signer's public key is not in your keyring. "
                + "Get the key from the sender (or with gpg --recv-keys \(fpr)), import it, then compare its "
                + "fingerprint with the sender through another channel."
        } else if SignerPresentation.isVerified(context.validity) {
            hint = nil
        } else {
            hint = "This key is not verified. Compare the fingerprint above with the sender through another channel "
                + "(in person, by phone, on their website). If it matches, certify the key locally:\n"
                + "gpg --lsign-key \(fpr)"
        }
    }

    static func validityText(_ context: SignerContext) -> String {
        if context.status == .noPublicKey { return "Unknown (not in your keyring)" }
        switch context.validity {
        case .ultimate: return "Verified (ultimate trust, your own key)"
        case .fully: return "Verified"
        case .marginal: return "Not verified (marginal validity)"
        case .never: return "Not trusted (marked as never valid)"
        case .undefined, nil: return "Not verified"
        }
    }

    static func statusText(_ status: SignatureStatus) -> String {
        switch status {
        case .good: return "Good signature"
        case .bad: return "Invalid signature (the message was changed)"
        case .expiredSignature: return "Expired signature"
        case .expiredKey: return "Good signature, but the key has expired"
        case .revokedKey: return "Good signature, but the key has been revoked"
        case .noPublicKey: return "Not checked (unknown key)"
        case .error: return "Not checked (error)"
        }
    }

    public static func defaultDate(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .standard)
    }
}

public enum Fingerprint {
    /// Upper-case hex in blocks of four: "ABCD 1234 …".
    public static func grouped(_ fingerprint: String) -> String {
        let hex = fingerprint.uppercased().filter { !$0.isWhitespace }
        var blocks: [String] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let end = hex.index(index, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            blocks.append(String(hex[index..<end]))
            index = end
        }
        return blocks.joined(separator: " ")
    }
}

/// A small in-memory LRU of message bytes keyed by `MessageContext.hash`. Holds ciphertext only (messages
/// waiting for an interactive decrypt) and never writes anything to disk.
public final class MessageByteCache: @unchecked Sendable {
    public let capacity: Int
    private let lock = NSLock()
    private var entries: [(hash: String, data: Data)] = []

    public init(capacity: Int = 5) {
        self.capacity = capacity
    }

    public func insert(_ data: Data, hash: String) {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll { $0.hash == hash }
        entries.append((hash, data))
        if entries.count > capacity { entries.removeFirst(entries.count - capacity) }
    }

    public func data(forHash hash: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard let index = entries.firstIndex(where: { $0.hash == hash }) else { return nil }
        let entry = entries.remove(at: index)
        entries.append(entry)
        return entry.data
    }

    public func remove(hash: String) {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll { $0.hash == hash }
    }
}

/// The readable text of a message decrypted on explicit request although its encrypted parts were mixed with other
/// content. Only shown in Sigil's own plain-text view: never handed back to Mail as message content (no HTML, no
/// remote content, nothing a reply or forward could quote).
public enum MixedDecryption {
    public static func readableText(of decodedMessage: Data) -> String {
        let root = MIMEEntity(data: RFC822Message(data: decodedMessage).bodyEntity)
        var parts: [String] = []
        for leaf in root.leaves {
            if leaf.contentType.mimeType == "text/plain", !leaf.isAttachment, let text = leaf.text {
                parts.append(text.trimmingCharacters(in: .whitespacesAndNewlines))
            } else if !leaf.rawBody.allSatisfy(PGPMIMEDecoder.isWhitespace) {
                parts.append("[\(leaf.contentType.mimeType) part not shown]")
            }
        }
        return parts.filter { !$0.isEmpty }.joined(separator: "\n\n――――\n\n")
    }
}
