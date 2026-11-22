import Foundation

/// A stored preference for an address; `usable` is false when the key can no longer be used for it.
public struct PreferredKeyEntry: Codable, Sendable, Equatable {
    public var email: String
    public var fingerprint: String
    public var usable: Bool

    public init(email: String, fingerprint: String, usable: Bool) {
        self.email = email
        self.fingerprint = fingerprint
        self.usable = usable
    }
}

/// The preferred encryption key per address, kept as `preferred-keys.json` (lower-case address -> upper-case
/// fingerprint) in the App Group container. The helper is the only writer.
public final class PreferredKeyStore: @unchecked Sendable {
    public static let fileName = "preferred-keys.json"

    public let fileURL: URL
    private let lock = NSLock()

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    public static func inAppGroup(_ appGroupID: String) -> PreferredKeyStore? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
            .map { PreferredKeyStore(fileURL: $0.appendingPathComponent(fileName)) }
    }

    public func all() -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        return read()
    }

    public func fingerprint(for email: String) -> String? { all()[email.lowercased()] }

    /// Sets the preference for an address; a nil fingerprint clears it.
    public func set(email: String, fingerprint: String?) throws {
        lock.lock(); defer { lock.unlock() }
        var map = read()
        map[email.lowercased()] = fingerprint.map { $0.uppercased().filter { !$0.isWhitespace } }
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try SafeFile.write(try JSONEncoder().encode(map), to: fileURL)
    }

    /// Empty when the file is missing, unreadable or a symbolic link.
    private func read() -> [String: String] {
        guard let data = try? SafeFile.read(fileURL) else { return [:] }
        return (try? JSONDecoder().decode([String: String].self, from: data)) ?? [:]
    }
}

/// The key for a recipient address, or why there is none.
public enum RecipientKeyResolution: Equatable, Sendable {
    case missing
    case key(KeyInfo)
    /// Several usable keys, none verified or preferred: Sigil does not guess (a planted key would win as "newest").
    case ambiguous([KeyInfo])

    public var key: KeyInfo? {
        if case let .key(key) = self { return key }
        return nil
    }
}

/// Picks the single encryption key for a recipient address.
public enum RecipientKeyChoice {
    /// User ID validity letters that make a user ID unusable (revoked, expired, invalid, disabled).
    static let unusableUIDValidities: Set<String> = ["r", "e", "i", "d"]

    /// True when a user ID of `key` matching `email` is fully or ultimately valid.
    static func isVerified(_ key: KeyInfo, for email: String) -> Bool {
        key.userIDs.contains { $0.email == email && ["f", "u"].contains($0.validity) }
    }

    /// A key that is not revoked, expired, disabled or invalid, can encrypt, and has a matching user ID that is not
    /// revoked, expired or invalid.
    public static func isUsableEncryptionKey(_ key: KeyInfo, for email: String) -> Bool {
        key.isUsable && key.capabilities.encrypt
            && key.userIDs.contains { $0.email == email && !unusableUIDValidities.contains($0.validity) }
    }

    /// Creation date of the newest encryption-capable subkey, else of the primary key.
    static func encryptionKeyCreated(_ key: KeyInfo) -> Date {
        let subkeys = key.subkeys.filter { $0.capabilities.encrypt }.compactMap(\.created)
        return subkeys.max() ?? key.created ?? .distantPast
    }

    /// The key to encrypt to: the preferred key (if usable); else, with several usable keys of which none is
    /// verified, `.ambiguous`; else `choose` (one unverified key is used and marked in compose).
    public static func resolve(from keys: [KeyInfo], email: String, preferred: String?) -> RecipientKeyResolution {
        let usable = keys.filter { isUsableEncryptionKey($0, for: email) }
        guard !usable.isEmpty else { return .missing }
        if let preferred = preferred?.uppercased(), let key = usable.first(where: { $0.fingerprint.uppercased() == preferred }) {
            return .key(key)
        }
        if usable.count > 1 && !usable.contains(where: { isVerified($0, for: email) }) { return .ambiguous(usable) }
        return choose(from: usable, email: email, preferred: nil).map(RecipientKeyResolution.key) ?? .missing
    }

    /// Order: the preferred key (if usable), then verified over unverified, then the newest, then the lowest
    /// fingerprint. `resolve` adds the ambiguity rule on top.
    public static func choose(from keys: [KeyInfo], email: String, preferred: String?) -> KeyInfo? {
        let usable = keys.filter { isUsableEncryptionKey($0, for: email) }
        if let preferred = preferred?.uppercased(), let key = usable.first(where: { $0.fingerprint.uppercased() == preferred }) {
            return key
        }
        return usable.min { a, b in
            let (va, vb) = (isVerified(a, for: email), isVerified(b, for: email))
            if va != vb { return va }
            let (ca, cb) = (encryptionKeyCreated(a), encryptionKeyCreated(b))
            if ca != cb { return ca > cb }
            return a.fingerprint.uppercased() < b.fingerprint.uppercased()
        }
    }
}
