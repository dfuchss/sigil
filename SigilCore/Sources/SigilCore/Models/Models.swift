import Foundation

public struct KeyCapabilities: Codable, Sendable, Hashable {
    public var sign: Bool
    public var encrypt: Bool
    public var certify: Bool
    public var authenticate: Bool

    public init(sign: Bool = false, encrypt: Bool = false, certify: Bool = false, authenticate: Bool = false) {
        self.sign = sign
        self.encrypt = encrypt
        self.certify = certify
        self.authenticate = authenticate
    }

    /// Parses a colons capability field. `usable == true` reads the uppercase (key-wide, usable) letters.
    public init(field: String, usable: Bool) {
        let set = Set(field.filter { usable ? $0.isUppercase : $0.isLowercase }.lowercased())
        self.init(sign: set.contains("s"), encrypt: set.contains("e"), certify: set.contains("c"), authenticate: set.contains("a"))
    }
}

public struct UserID: Codable, Sendable, Hashable {
    public var uid: String
    public var name: String?
    public var email: String?
    /// Raw colons validity letter (o, i, d, r, e, -, q, n, m, f, u, w, s).
    public var validity: String

    public init(uid: String, validity: String) {
        self.uid = uid
        self.validity = validity
        let parsed = EmailAddress.parse(uid)
        self.name = parsed.name
        self.email = parsed.email
    }
}

public struct SubkeyInfo: Codable, Sendable, Hashable {
    public var fingerprint: String
    public var keyID: String
    public var validity: String
    public var algorithm: Int
    public var length: Int
    public var created: Date?
    public var expires: Date?
    public var capabilities: KeyCapabilities
}

public struct KeyInfo: Codable, Sendable, Hashable {
    public var fingerprint: String
    public var keyID: String
    /// True when listed as a secret key (`sec`).
    public var isSecret: Bool
    /// Raw colons validity letter of the primary key.
    public var validity: String
    public var ownerTrust: String
    public var algorithm: Int
    public var length: Int
    public var curve: String?
    public var created: Date?
    public var expires: Date?
    /// Key-wide usable capabilities (uppercase letters of the primary record; includes subkeys).
    public var capabilities: KeyCapabilities
    public var isDisabled: Bool
    public var userIDs: [UserID]
    public var subkeys: [SubkeyInfo]

    public var isRevoked: Bool { validity == "r" }
    public var isExpired: Bool { validity == "e" }
    public var isInvalid: Bool { validity == "i" }
    public var emails: [String] { userIDs.compactMap { $0.email } }
    public var primaryUserID: UserID? { userIDs.first }

    /// Not revoked/expired/disabled/invalid.
    public var isUsable: Bool { !isRevoked && !isExpired && !isDisabled && !isInvalid }

    /// Sigil only works with keys through their email user IDs: drops user IDs without a parseable email
    /// ("Name <addr>" or a bare "addr@domain"), then keys left without any user ID. A key whose only user ID is a
    /// name can therefore never be listed, chosen as sender or recipient, or matched by fingerprint or name.
    public static func withEmailUserIDsOnly(_ keys: [KeyInfo]) -> [KeyInfo] {
        keys.compactMap { key in
            var kept = key
            kept.userIDs = key.userIDs.filter { $0.email != nil }
            return kept.userIDs.isEmpty ? nil : kept
        }
    }
}

public enum TrustLevel: String, Codable, Sendable {
    case undefined, never, marginal, fully, ultimate
}

public enum SignatureStatus: String, Codable, Sendable {
    case good
    case bad
    case expiredSignature
    case expiredKey
    case revokedKey
    case noPublicKey
    case error
}

public struct SignatureResult: Codable, Sendable, Equatable {
    public var status: SignatureStatus
    public var keyID: String?
    public var fingerprint: String?
    public var primaryFingerprint: String?
    public var userID: String?
    public var trust: TrustLevel?
    public var created: Date?
    /// ERRSIG return code (9 = no public key, 4 = unknown algorithm).
    public var errorCode: Int?

    public init(status: SignatureStatus, keyID: String? = nil, fingerprint: String? = nil, primaryFingerprint: String? = nil,
                userID: String? = nil, trust: TrustLevel? = nil, created: Date? = nil, errorCode: Int? = nil) {
        self.status = status
        self.keyID = keyID
        self.fingerprint = fingerprint
        self.primaryFingerprint = primaryFingerprint
        self.userID = userID
        self.trust = trust
        self.created = created
        self.errorCode = errorCode
    }

    public var email: String? { userID.flatMap { EmailAddress.parse($0).email } }
}

public struct DecryptResult: Codable, Sendable {
    public var plaintext: Data
    /// False when the input only contained signed (not encrypted) data.
    public var wasEncrypted: Bool
    public var signatures: [SignatureResult]
    /// Key IDs from ENC_TO (hidden recipients appear as 0000000000000000).
    public var encryptedTo: [String]
    public var integrityProtected: Bool

    public init(plaintext: Data, wasEncrypted: Bool, signatures: [SignatureResult], encryptedTo: [String], integrityProtected: Bool) {
        self.plaintext = plaintext
        self.wasEncrypted = wasEncrypted
        self.signatures = signatures
        self.encryptedTo = encryptedTo
        self.integrityProtected = integrityProtected
    }
}

public struct EncodingStatus: Codable, Sendable, Equatable {
    public var canSign: Bool
    public var signerFingerprint: String?
    public var missingRecipients: [String]
    /// True when at least one recipient is given and none is missing.
    public var canEncrypt: Bool
    /// Recipients that have a usable key, but whose key validity is below full (e.g. an imported, uncertified key).
    /// Encryption to them works; compose should mark them as unverified.
    public var unverifiedRecipients: [String]
    /// Recipients with more than one usable key, none of them verified or preferred: Sigil will not guess, so
    /// encrypting refuses until the user picks one (Public Keys > Prefer). They are not in `unverifiedRecipients`.
    public var ambiguousRecipients: [String]

    public init(canSign: Bool, signerFingerprint: String?, missingRecipients: [String], canEncrypt: Bool,
                unverifiedRecipients: [String] = [], ambiguousRecipients: [String] = []) {
        self.ambiguousRecipients = ambiguousRecipients
        self.canSign = canSign
        self.signerFingerprint = signerFingerprint
        self.missingRecipients = missingRecipients
        self.canEncrypt = canEncrypt
        self.unverifiedRecipients = unverifiedRecipients
    }
}

public struct SignerInfo: Codable, Sendable, Equatable {
    public var fingerprint: String?
    public var keyID: String?
    /// Email of the signing key; prefers the uid matching the message's From address.
    public var email: String?
    public var userID: String?
    /// Validity of the signing key (from TRUST_*), nil if unknown.
    public var validity: TrustLevel?
    public var status: SignatureStatus
    /// Signature creation time, if gpg reported it.
    public var created: Date?
    /// Whether an email user ID of the signing key is the message's From address; nil when that cannot be
    /// determined (unknown key or no From address).
    public var matchesSender: Bool?

    public init(fingerprint: String?, keyID: String?, email: String?, userID: String?, validity: TrustLevel?,
                status: SignatureStatus, created: Date? = nil, matchesSender: Bool? = nil) {
        self.matchesSender = matchesSender
        self.fingerprint = fingerprint
        self.keyID = keyID
        self.email = email
        self.userID = userID
        self.validity = validity
        self.status = status
        self.created = created
    }
}

public struct DecodeOutcome: Codable, Sendable {
    /// The decoded RFC 822 message (outer headers + plaintext body entity). Nil on decryption failure.
    public var message: Data?
    public var classification: MessageClassification
    public var encrypted: Bool
    public var signed: Bool
    /// True when only a part of the message was signed/encrypted (do not present it as fully signed).
    public var partial: Bool
    public var signers: [SignerInfo]
    public var error: String?
    public var needsPassphrase: Bool
    /// Encrypted parts are mixed with other content (or there are several): nothing was decrypted and `message` is
    /// the original. Decrypting needs an explicit user request (EFAIL).
    public var mixedEncryption: Bool

    public init(message: Data?, classification: MessageClassification, encrypted: Bool, signed: Bool, partial: Bool,
                signers: [SignerInfo], error: String?, needsPassphrase: Bool, mixedEncryption: Bool = false) {
        self.mixedEncryption = mixedEncryption
        self.message = message
        self.classification = classification
        self.encrypted = encrypted
        self.signed = signed
        self.partial = partial
        self.signers = signers
        self.error = error
        self.needsPassphrase = needsPassphrase
    }
}

/// JSON coding used across the XPC boundary (Data as base64, dates as seconds since 1970).
public enum SigilJSON {
    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .secondsSince1970
        e.outputFormatting = [.sortedKeys]
        return e
    }

    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .secondsSince1970
        return d
    }
}

public enum EmailAddress {
    /// Parses "Name <addr>" or a bare address; returns lowercased email.
    public static func parse(_ s: String) -> (name: String?, email: String?) {
        let t = s.trimmingCharacters(in: .whitespaces)
        if let lt = t.lastIndex(of: "<"), let gt = t[lt...].firstIndex(of: ">") {
            let email = t[t.index(after: lt)..<gt].trimmingCharacters(in: .whitespaces).lowercased()
            var name = t[..<lt].trimmingCharacters(in: .whitespaces)
            if name.hasPrefix("\""), name.hasSuffix("\""), name.count >= 2 { name = String(name.dropFirst().dropLast()) }
            return (name.isEmpty ? nil : name, email.contains("@") ? email : nil)
        }
        if t.contains("@"), !t.contains(" ") { return (nil, t.lowercased()) }
        return (t.isEmpty ? nil : t, nil)
    }

    /// Extracts the address from a header-style value, falling back to the trimmed input.
    public static func extract(_ s: String) -> String {
        parse(s).email ?? s.trimmingCharacters(in: .whitespaces).lowercased()
    }
}
