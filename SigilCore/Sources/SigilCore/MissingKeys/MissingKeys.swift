import Foundation

/// A signing key Sigil could not find while verifying an incoming message. Only key data and the sender address
/// are kept: never a subject, content or Message-ID.
public struct MissingKeyEntry: Codable, Sendable, Equatable, Identifiable {
    /// 16 hex digits, upper case.
    public var keyID: String
    /// Issuer fingerprint (40 or 64 hex digits, upper case) when the signature carried one.
    public var fingerprint: String?
    /// The From address of the latest message signed with this key.
    public var senderEmail: String?
    /// The signer user ID, only when it carries an email address.
    public var signerUserID: String?
    public var firstSeen: Date
    public var lastSeen: Date
    /// Distinct messages seen with this key (in one helper run; repeated decodes of a message count once).
    public var count: Int
    public var dismissed: Bool

    /// Stable reference used by the XPC calls: the fingerprint if known, else the key ID.
    public var id: String { fingerprint ?? keyID }

    public init(keyID: String, fingerprint: String?, senderEmail: String?, signerUserID: String?,
                firstSeen: Date, lastSeen: Date, count: Int, dismissed: Bool) {
        self.keyID = keyID
        self.fingerprint = fingerprint
        self.senderEmail = senderEmail
        self.signerUserID = signerUserID
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.count = count
        self.dismissed = dismissed
    }

    /// Same key: equal fingerprints when both are known, otherwise equal key IDs.
    func isSameKey(keyID otherKeyID: String, fingerprint otherFingerprint: String?) -> Bool {
        if let fingerprint, let otherFingerprint { return fingerprint == otherFingerprint }
        return keyID == otherKeyID
    }

    /// Upper-case hex without spaces.
    static func normalizedHex(_ s: String?) -> String? {
        guard let hex = s?.uppercased().filter({ !$0.isWhitespace }), !hex.isEmpty, hex.allSatisfy(\.isHexDigit)
        else { return nil }
        return hex
    }

    /// The 16-digit key ID: given directly, or derived from a fingerprint (v4: last 16, v5/v6: first 16 digits).
    static func keyID(from keyID: String?, fingerprint: String?) -> String? {
        if let id = normalizedHex(keyID), id.count == 16 { return id }
        guard let fpr = normalizedHex(fingerprint ?? keyID) else { return nil }
        if fpr.count == 40 { return String(fpr.suffix(16)) }
        if fpr.count == 64 { return String(fpr.prefix(16)) }
        return nil
    }
}

/// The list of missing keys, kept as `missing-keys.json` in the App Group container. Every change is a
/// read-modify-write under an in-process lock plus an exclusive `flock` on a sidecar lock file, written atomically,
/// so concurrent writers (helper connections, or another process) never lose updates or see a half-written file.
/// In practice only the helper writes: the app dismisses, restores and fetches through XPC.
public final class MissingKeyStore: @unchecked Sendable {
    public static let fileName = "missing-keys.json"

    public let fileURL: URL
    private let lock = NSLock()

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    /// The store in the App Group container, nil if the process has no access to that group.
    public static func inAppGroup(_ appGroupID: String) -> MissingKeyStore? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
            .map { MissingKeyStore(fileURL: $0.appendingPathComponent(fileName)) }
    }

    public func entries() -> [MissingKeyEntry] {
        (try? withLockedFile { try MissingKeyStore.read(fileURL) }) ?? []
    }

    public func entry(id: String) -> MissingKeyEntry? {
        entries().first { $0.id == id }
    }

    /// Adds a sighting of a key, merging by fingerprint (if known on both sides) or key ID. A dismissed entry stays
    /// dismissed; its count and last-seen date still update. Returns false when the key reference is unusable.
    @discardableResult
    public func record(keyID rawKeyID: String?, fingerprint rawFingerprint: String?, senderEmail: String?,
                       signerUserID: String?, at date: Date = Date()) throws -> Bool {
        let fingerprint = MissingKeyEntry.normalizedHex(rawFingerprint).flatMap { [40, 64].contains($0.count) ? $0 : nil }
        guard let keyID = MissingKeyEntry.keyID(from: rawKeyID, fingerprint: fingerprint) else { return false }
        let userID = signerUserID.flatMap { EmailAddress.parse($0).email == nil ? nil : $0 }
        try update { entries in
            if let index = entries.firstIndex(where: { $0.isSameKey(keyID: keyID, fingerprint: fingerprint) }) {
                entries[index].count += 1
                entries[index].lastSeen = max(entries[index].lastSeen, date)
                entries[index].fingerprint = entries[index].fingerprint ?? fingerprint
                if let senderEmail { entries[index].senderEmail = senderEmail }
                if let userID { entries[index].signerUserID = userID }
            } else {
                entries.append(MissingKeyEntry(keyID: keyID, fingerprint: fingerprint, senderEmail: senderEmail,
                                               signerUserID: userID, firstSeen: date, lastSeen: date, count: 1,
                                               dismissed: false))
            }
        }
        return true
    }

    /// Dismisses (or restores) an entry; false if there is no entry with that id.
    @discardableResult
    public func setDismissed(id: String, _ dismissed: Bool) throws -> Bool {
        try update { entries in
            guard let index = entries.firstIndex(where: { $0.id == id }) else { return false }
            entries[index].dismissed = dismissed
            return true
        }
    }

    /// Removes an entry (its key was fetched).
    public func remove(id: String) throws {
        try update { entries in entries.removeAll { $0.id == id } }
    }

    /// Deletes a dismissed entry for good; false if there is no such entry or it is not dismissed (active entries
    /// are never removed this way). The key comes back as a new, not dismissed entry when it is recorded again.
    @discardableResult
    public func removeDismissed(id: String) throws -> Bool {
        try update { entries in
            guard let index = entries.firstIndex(where: { $0.id == id && $0.dismissed }) else { return false }
            entries.remove(at: index)
            return true
        }
    }

    /// Deletes every dismissed entry; returns how many were removed.
    @discardableResult
    public func removeAllDismissed() throws -> Int {
        try update { entries in
            let before = entries.count
            entries.removeAll { $0.dismissed }
            return before - entries.count
        }
    }

    // MARK: File access

    @discardableResult
    private func update<T>(_ change: (inout [MissingKeyEntry]) throws -> T) throws -> T {
        try withLockedFile {
            var entries = try MissingKeyStore.read(fileURL)
            let before = entries
            let result = try change(&entries)
            if entries != before {
                try SafeFile.write(try SigilJSON.encoder().encode(entries), to: fileURL)
            }
            return result
        }
    }

    private func withLockedFile<T>(_ body: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let lockPath = fileURL.path + ".lock"
        // O_NOFOLLOW: a symbolic link planted as the lock file is refused instead of creating or opening its target.
        let descriptor = open(lockPath, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else {
            if errno == ELOOP { throw SafeFile.SymlinkRefused(path: lockPath) }
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: lockPath])
        }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else {
            throw CocoaError(.fileLocking, userInfo: [NSFilePathErrorKey: lockPath])
        }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }

    /// Throws for a symbolic link (never followed); a missing or unreadable file is empty.
    private static func read(_ url: URL) throws -> [MissingKeyEntry] {
        guard let data = try SafeFile.read(url) else { return [] }
        return (try? SigilJSON.decoder().decode([MissingKeyEntry].self, from: data)) ?? []
    }
}

/// Records unknown signing keys after a decode, counting each message once. The message hashes used for that live
/// in memory only (bounded), never on disk.
public final class MissingKeyRecorder: @unchecked Sendable {
    public let store: MissingKeyStore
    public let capacity: Int
    private let lock = NSLock()
    private var seen: [String] = []
    private var seenSet: Set<String> = []

    public init(store: MissingKeyStore, capacity: Int = 1000) {
        self.store = store
        self.capacity = capacity
    }

    /// Records every unknown-key signer of a successfully decoded message. Returns the number of new sightings.
    @discardableResult
    public func record(outcome: DecodeOutcome, message: Data, at date: Date = Date()) -> Int {
        guard outcome.message != nil else { return 0 }
        let unknown = outcome.signers.filter { $0.status == .noPublicKey }
        guard !unknown.isEmpty else { return 0 }
        let messageHash = MessageContext.hash(of: message)
        let sender = RFC822Message(data: message).header("From").flatMap { EmailAddress.parse($0).email }
        var recorded = 0
        for signer in unknown {
            guard let keyID = MissingKeyEntry.keyID(from: signer.keyID, fingerprint: signer.fingerprint),
                  firstSighting(messageHash + ":" + keyID) else { continue }
            if (try? store.record(keyID: keyID, fingerprint: signer.fingerprint, senderEmail: sender,
                                  signerUserID: signer.userID, at: date)) == true {
                recorded += 1
            }
        }
        return recorded
    }

    private func firstSighting(_ key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard seenSet.insert(key).inserted else { return false }
        seen.append(key)
        if seen.count > capacity { seenSet.remove(seen.removeFirst()) }
        return true
    }
}

// MARK: - Fetching

public struct KeyFetchError: LocalizedError, Equatable, Sendable {
    public var message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public enum MissingKeyMatch {
    /// True when `key` (its primary key or a subkey; signatures are usually made by a subkey) is the entry's key:
    /// by fingerprint when the entry has one, otherwise by key ID.
    public static func matches(_ key: KeyInfo, _ entry: MissingKeyEntry) -> Bool {
        if let fingerprint = entry.fingerprint {
            return ([key.fingerprint] + key.subkeys.map(\.fingerprint)).contains { $0.uppercased() == fingerprint }
        }
        return ([key.keyID] + key.subkeys.map(\.keyID)).contains { $0.uppercased() == entry.keyID }
    }
}

/// A short-lived GnuPG home for retrieving keys without touching the user's keyring.
struct IsolatedGPGHome: Sendable {
    static let namePrefix = "sigil-fetch-"
    let url: URL

    /// Creates the directory under /tmp (short path: gpg-agent and dirmngr sockets live inside and are limited to
    /// about 100 bytes) with mode 0700 and writes a minimal gpg.conf and dirmngr.conf with only the lookup options of
    /// the user's files (`TempHomeConfig`), so their keyserver and auto-key-locate settings still apply but nothing
    /// else (other keyrings, extensions, home directories) does.
    static func make(copyingConfigFrom runner: GPGRunner) throws -> IsolatedGPGHome {
        var template = Array("/tmp/\(namePrefix)XXXXXX".utf8CString)
        guard let path = mkdtemp(&template) else { throw KeyFetchError("could not create a temporary GnuPG home") }
        let home = IsolatedGPGHome(url: URL(fileURLWithPath: String(cString: path), isDirectory: true))
        let source = try? runner.homeDirectory()
        func text(_ name: String) -> String {
            guard let source, let data = try? SafeFile.read(source.appendingPathComponent(name)) else { return "" }
            return String(decoding: data, as: UTF8.self)
        }
        let files = [("gpg.conf", TempHomeConfig.filteredGPGConf(text("gpg.conf"))),
                     ("dirmngr.conf", TempHomeConfig.filteredDirmngrConf(text("dirmngr.conf")))]
        for (name, contents) in files {
            FileManager.default.createFile(atPath: home.url.appendingPathComponent(name).path, contents: Data(contents.utf8),
                                           attributes: [.posixPermissions: 0o600])
        }
        return home
    }

    func destroy(using runner: GPGRunner) {
        IsolatedGPGHome.kill(url, gpgconf: runner.gpgconfPath)
        try? FileManager.default.removeItem(at: url)
    }

    static func kill(_ home: URL, gpgconf: URL?) {
        guard let gpgconf else { return }
        let process = Process()
        process.executableURL = gpgconf
        process.arguments = ["--homedir", home.path, "--kill", "all"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        if (try? process.run()) != nil { process.waitUntilExit() }
    }

    /// Deletes leftover temporary homes (the helper was killed during a search): directories in `directory` named
    /// `sigil-fetch-*`, owned by this user, not symbolic links, last changed more than `age` ago. Their agents are
    /// stopped first. Returns how many were removed. Run at helper startup.
    @discardableResult
    static func removeStale(in directory: String = "/tmp", olderThan age: TimeInterval = 3600, gpgconf: URL?,
                            now: Date = Date()) -> Int {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
        var removed = 0
        for name in names where name.hasPrefix(namePrefix) {
            let path = (directory as NSString).appendingPathComponent(name)
            var info = stat()
            guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == getuid() else { continue }
            let changed = Date(timeIntervalSince1970: TimeInterval(info.st_mtimespec.tv_sec))
            guard now.timeIntervalSince(changed) > age else { continue }
            let url = URL(fileURLWithPath: path, isDirectory: true)
            kill(url, gpgconf: gpgconf)
            if (try? FileManager.default.removeItem(at: url)) != nil { removed += 1 }
        }
        return removed
    }
}

public enum KeySearchCleanup {
    /// Removes temporary key-search homes older than an hour (see `IsolatedGPGHome.removeStale`).
    @discardableResult
    public static func removeStaleHomes(gpgconf: URL?) -> Int {
        IsolatedGPGHome.removeStale(gpgconf: gpgconf)
    }
}

/// The configuration of a temporary key-search home: allowlisted lookup options from the user's files.
public enum TempHomeConfig {
    public static let gpgOptions: Set<String> = ["keyserver", "auto-key-locate", "keyserver-options", "trust-model"]
    public static let dirmngrOptions: Set<String> = ["keyserver", "hkp-cacert", "honor-http-proxy", "http-proxy", "use-tor",
                                                     "standard-resolver", "resolver-timeout"]
    /// `keyserver-options` values that only tune the lookup; anything else (honor-keyserver-url, auto-key-retrieve,
    /// unknown options) is dropped.
    public static let keyserverOptionValues: Set<String> = [
        "timeout", "http-proxy", "include-subkeys", "no-include-subkeys", "include-revoked", "no-include-revoked",
        "include-disabled", "no-include-disabled", "no-honor-keyserver-url", "no-auto-key-retrieve",
    ]

    public static func filteredGPGConf(_ text: String) -> String {
        filtered(text, allowed: gpgOptions)
    }

    public static func filteredDirmngrConf(_ text: String) -> String {
        filtered(text, allowed: dirmngrOptions)
    }

    static func filtered(_ text: String, allowed: Set<String>) -> String {
        var lines = ["# Written by Sigil for a temporary key search: allowlisted options of your configuration."]
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            var name = String(line.prefix { !$0.isWhitespace && $0 != "=" }).lowercased()
            var value = line.dropFirst(name.count).trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("=") { value = value.dropFirst().trimmingCharacters(in: .whitespaces) }
            if name.hasPrefix("--") { name = String(name.dropFirst(2)) }
            guard allowed.contains(name) else { continue }
            if name == "keyserver-options" {
                let kept = value.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init).filter {
                    keyserverOptionValues.contains(String($0.prefix { $0 != "=" }).lowercased())
                }
                guard !kept.isEmpty else { continue }
                value = kept.joined(separator: ",")
            }
            lines.append(value.isEmpty ? name : "\(name) \(value)")
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
