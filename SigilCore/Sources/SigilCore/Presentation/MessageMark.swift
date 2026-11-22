import Foundation

/// How strongly a received message is flagged for a signature or integrity problem: the message-list colour
/// and the colour of the warning box in the decoded message. The worst problem wins.
public enum MessageMark: Int, Comparable, Sendable {
    case none, yellow, red

    public static func < (lhs: MessageMark, rhs: MessageMark) -> Bool { lhs.rawValue < rhs.rawValue }

    /// - red: a BAD signature, or ciphertext that failed its integrity check (modified).
    /// - yellow: revoked/expired/unknown/distrusted key, expired signature, a signature that could not be
    ///   checked, a good signature from a key without the From address, or only part of the message signed.
    /// - none: good signatures (verified or not), plain decrypted mail, a passphrase still needed, not PGP.
    public static func of(_ outcome: DecodeOutcome) -> MessageMark {
        if outcome.needsPassphrase { return .none }
        var mark = outcome.signers.map(of).max() ?? .none
        if outcome.message == nil, let error = outcome.error {
            if outcome.encrypted {
                if isIntegrityError(error) { mark = .red }
            } else {
                mark = max(mark, .yellow) // a signed message that could not be checked at all
            }
        }
        if outcome.partial && outcome.signed { mark = max(mark, .yellow) }
        return mark
    }

    static func of(_ signer: SignerInfo) -> MessageMark {
        switch signer.status {
        case .good: return signer.validity == .never || signer.matchesSender == false ? .yellow : .none
        case .bad: return .red
        case .expiredSignature, .expiredKey, .revokedKey, .noPublicKey, .error: return .yellow
        }
    }

    /// Matches `GPGError.integrityCheckFailed` (the helper sends errors as text).
    static func isIntegrityError(_ error: String) -> Bool {
        let text = error.lowercased()
        return text.contains("integrity") || text.contains("modified") || text.contains("manipulated")
    }
}
