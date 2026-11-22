import Foundation

// MARK: - Manual query

/// What the user typed into "Find Key": an email address, a fingerprint (40/64 hex digits) or a 16-digit key ID.
public enum KeyQuery: Equatable, Sendable {
    case email(String)
    case fingerprint(String)
    case keyID(String)

    /// nil for anything else; gpg is never called with an unvalidated query.
    public static func parse(_ text: String) -> KeyQuery? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        var hexText = trimmed.filter { !$0.isWhitespace }
        if hexText.lowercased().hasPrefix("0x") { hexText = String(hexText.dropFirst(2)) }
        if let hex = MissingKeyEntry.normalizedHex(hexText) {
            switch hex.count {
            case 16: return .keyID(hex)
            case 40, 64: return .fingerprint(hex)
            default: return nil
            }
        }
        guard trimmed.contains("@"), let email = EmailAddress.parse(trimmed).email else { return nil }
        let parts = email.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, parts[1].count >= 1, !parts[1].hasPrefix("."), !parts[1].hasSuffix("."),
              !email.hasPrefix("-"), !email.contains(where: \.isWhitespace) else { return nil }
        return .email(email)
    }

    public var email: String? {
        if case let .email(address) = self { return address }
        return nil
    }

    /// The pseudo entry the search session works with: no signature to match, only the query.
    var pseudoEntry: MissingKeyEntry {
        let now = Date()
        switch self {
        case let .email(address):
            return MissingKeyEntry(keyID: "0000000000000000", fingerprint: nil, senderEmail: address,
                                   signerUserID: nil, firstSeen: now, lastSeen: now, count: 0, dismissed: false)
        case let .fingerprint(hex):
            return MissingKeyEntry(keyID: MissingKeyEntry.keyID(from: nil, fingerprint: hex) ?? hex, fingerprint: hex,
                                   senderEmail: nil, signerUserID: nil, firstSeen: now, lastSeen: now, count: 0,
                                   dismissed: false)
        case let .keyID(hex):
            return MissingKeyEntry(keyID: hex, fingerprint: nil, senderEmail: nil, signerUserID: nil,
                                   firstSeen: now, lastSeen: now, count: 0, dismissed: false)
        }
    }
}

// MARK: - Candidates

/// One key found while looking for a missing signing key. Nothing here has touched the user's keyring.
public struct KeyCandidate: Codable, Sendable, Equatable, Identifiable {
    public struct UID: Codable, Sendable, Equatable {
        public var uid: String
        public var email: String?
        public init(uid: String) {
            self.uid = uid
            self.email = EmailAddress.parse(uid).email
        }
    }

    /// Fingerprint (40/64 hex digits); a keyserver may only report the 16-digit key ID, which is then kept here.
    public var fingerprint: String
    public var keyID: String
    public var userIDs: [UID]
    public var created: Date?
    public var expired: Bool
    public var revoked: Bool
    /// Where the key was found: `KeyCandidate.locateSource` ("auto-key-locate": gpg's own `--locate-external-keys`
    /// with the user's auto-key-locate mechanisms, typically WKD), "keyserver" or "recv-keys" (from the keyserver).
    public var sources: [String]
    /// The fingerprint, key ID or a subkey of the key is the one that signed the message.
    public var matchesSignature: Bool
    /// Manual search by fingerprint or key ID: this is the key that was asked for.
    public var matchesQuery: Bool
    /// The key is already in the user's keyring (importing again refreshes it).
    public var alreadyInKeyring: Bool

    public var id: String { fingerprint }

    public static let locateSource = "auto-key-locate"
    /// Only found on a keyserver (listing or recv-keys): the key itself may be the signer's, but nobody checked that
    /// its user IDs belong to the address.
    public var isKeyserverOnly: Bool { !sources.contains(KeyCandidate.locateSource) }
    public var hasEmailUserID: Bool { userIDs.contains { $0.email != nil } }

    public init(fingerprint: String, keyID: String, userIDs: [UID], created: Date?, expired: Bool, revoked: Bool,
                sources: [String], matchesSignature: Bool, matchesQuery: Bool = false, alreadyInKeyring: Bool = false) {
        self.matchesQuery = matchesQuery
        self.alreadyInKeyring = alreadyInKeyring
        self.fingerprint = fingerprint
        self.keyID = keyID
        self.userIDs = userIDs
        self.created = created
        self.expired = expired
        self.revoked = revoked
        self.sources = sources
        self.matchesSignature = matchesSignature
    }

    /// A candidate from a key in a GnuPG home (full information, subkeys included).
    static func make(_ key: KeyInfo, source: String, entry: MissingKeyEntry) -> KeyCandidate {
        KeyCandidate(fingerprint: key.fingerprint.uppercased(), keyID: key.keyID.uppercased(),
                     userIDs: key.userIDs.map { UID(uid: $0.uid) }, created: key.created,
                     expired: key.isExpired, revoked: key.isRevoked, sources: [source],
                     matchesSignature: MissingKeyMatch.matches(key, entry))
    }

    /// A candidate from a keyserver listing line (primary key only).
    static func make(_ hit: KeyServerHit, entry: MissingKeyEntry) -> KeyCandidate {
        let id = hit.id
        let keyID = MissingKeyEntry.keyID(from: id, fingerprint: id) ?? id
        let matches: Bool
        if let fingerprint = entry.fingerprint, id.count >= 40 { matches = id == fingerprint } else { matches = keyID == entry.keyID }
        return KeyCandidate(fingerprint: id, keyID: keyID, userIDs: hit.userIDs.map { UID(uid: $0) },
                            created: hit.created, expired: hit.expired, revoked: hit.revoked,
                            sources: ["keyserver"], matchesSignature: matches)
    }

    /// Merges candidates, deduplicated by fingerprint (a 16-digit key ID counts as the same key as a fingerprint
    /// ending in, or for v6 starting with, it). Full information from a gpg home wins over a keyserver listing.
    static func merge(_ lists: [[KeyCandidate]]) -> [KeyCandidate] {
        var merged: [KeyCandidate] = []
        for candidate in lists.flatMap({ $0 }) {
            guard let index = merged.firstIndex(where: { $0.isSameKey(as: candidate) }) else {
                merged.append(candidate)
                continue
            }
            var existing = merged[index]
            let preferNew = candidate.fingerprint.count > existing.fingerprint.count
            for source in candidate.sources where !existing.sources.contains(source) { existing.sources.append(source) }
            existing.matchesSignature = existing.matchesSignature || candidate.matchesSignature
            existing.matchesQuery = existing.matchesQuery || candidate.matchesQuery
            existing.alreadyInKeyring = existing.alreadyInKeyring || candidate.alreadyInKeyring
            if preferNew { existing.fingerprint = candidate.fingerprint }
            for uid in candidate.userIDs where !existing.userIDs.contains(uid) { existing.userIDs.append(uid) }
            existing.created = existing.created ?? candidate.created
            existing.expired = existing.expired || candidate.expired
            existing.revoked = existing.revoked || candidate.revoked
            merged[index] = existing
        }
        return merged
    }

    /// A non-expired, non-revoked key with a user ID for the sender's address.
    public func isValid(forSender email: String?) -> Bool {
        guard !expired, !revoked, let email else { return false }
        return userIDs.contains { $0.email?.lowercased() == email.lowercased() }
    }

    /// Ticked when the sheet opens: keys found through auto-key-locate (WKD, domain-verified) that signed the
    /// message or are valid for the sender. Keyserver-only keys are never ticked, not even the signing key: a
    /// keyserver may not verify addresses, so the user must choose them deliberately. Expired and revoked keys never
    /// are.
    public func isPreselected(forSender email: String?) -> Bool {
        if expired || revoked || isKeyserverOnly { return false }
        return matchesSignature || isValid(forSender: email)
    }

    /// Manual search: ticked when the sheet opens. Email query: valid keys WKD/locate found for that address.
    /// Fingerprint or key ID query: the exact match (unless expired or revoked). Keyserver-only hits for an email
    /// are not ticked.
    public func isPreselected(forQuery query: KeyQuery) -> Bool {
        if expired || revoked { return false }
        switch query {
        case let .email(address):
            return !isKeyserverOnly && isValid(forSender: address)
        case .fingerprint, .keyID:
            return matchesQuery
        }
    }

    /// Manual search, "Select all valid": not expired or revoked, and for an email query with that address.
    public func isValid(forQuery query: KeyQuery) -> Bool {
        if case let .email(address) = query { return isValid(forSender: address) }
        return !expired && !revoked && hasEmailUserID
    }

    func isSameKey(as other: KeyCandidate) -> Bool {
        if fingerprint == other.fingerprint { return true }
        guard fingerprint.count != other.fingerprint.count else { return false }
        return keyID == other.keyID
    }
}

/// The result of a search: the candidates and a token that refers to the temporary keyring holding them.
public struct KeySearchResult: Codable, Sendable, Equatable {
    public var token: String
    public var candidates: [KeyCandidate]
    /// gpg's own error text for the lookups that failed, shown when nothing was found.
    public var message: String?
    /// Per source (WKD, keyserver) why the lookup gave nothing, in plain text; only filled for failed lookups.
    public var problems: [SearchProblem]

    public init(token: String, candidates: [KeyCandidate], message: String?, problems: [SearchProblem] = []) {
        self.token = token
        self.candidates = candidates
        self.message = message
        self.problems = problems
    }
}

public struct KeyImportResult: Codable, Sendable, Equatable {
    public var fingerprint: String
    public var userIDs: [String]
    public var matchesSignature: Bool
    /// The missing-keys entry was removed (only when the imported key matches the signature).
    public var entryRemoved: Bool

    public init(fingerprint: String, userIDs: [String], matchesSignature: Bool, entryRemoved: Bool) {
        self.fingerprint = fingerprint
        self.userIDs = userIDs
        self.matchesSignature = matchesSignature
        self.entryRemoved = entryRemoved
    }
}

// MARK: - Keyserver listing

public struct KeyServerHit: Sendable, Equatable {
    public var id: String
    public var created: Date?
    public var expired: Bool
    public var revoked: Bool
    public var userIDs: [String]
}

/// Parses `gpg --with-colons --search-keys` output:
/// `info:<version>:<count>`, `pub:<fpr or keyid>:<algo>:<bits>:<created>:<expires>:<flags>` and
/// `uid:<percent-escaped uid>:<created>:<expires>:<flags>` (flags: r revoked, d disabled, e expired).
public enum KeyServerSearchParser {
    public static func parse(_ output: String) -> [KeyServerHit] {
        var hits: [KeyServerHit] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            switch fields.first {
            case "pub":
                guard fields.count > 1, let id = MissingKeyEntry.normalizedHex(fields[1]),
                      [16, 40, 64].contains(id.count) else { continue }
                let flags = fields.count > 6 ? fields[6] : ""
                hits.append(KeyServerHit(id: id, created: date(fields, 4), expired: flags.contains("e"),
                                         revoked: flags.contains("r"), userIDs: []))
            case "uid":
                guard fields.count > 1, !hits.isEmpty else { continue }
                let uid = fields[1].removingPercentEncoding ?? fields[1]
                if !uid.isEmpty { hits[hits.count - 1].userIDs.append(uid) }
            default:
                continue
            }
        }
        return hits
    }

    private static func date(_ fields: [String], _ index: Int) -> Date? {
        guard fields.count > index, let seconds = TimeInterval(fields[index]) else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }
}

// MARK: - Search session

/// A search and its temporary GnuPG home. The user's keyring is only touched by `importKey`, which exports exactly
/// the chosen fingerprint from the temporary home and imports it into the user's keyring.
final class KeySearchSession: @unchecked Sendable {
    /// Runs a gpg command in the temporary home with network lookups allowed (replaceable in tests).
    typealias Run = @Sendable (GPGRunner, [String]) throws -> GPGProcessResult

    let token = UUID().uuidString
    let entry: MissingKeyEntry
    /// A manual search ("Find Key"): there is no signature, so nothing matches it and no entry is removed.
    let isManual: Bool
    let store: MissingKeyStore?
    let target: GPGRunner
    let home: IsolatedGPGHome
    let temp: GPGRunner
    let run: Run
    private let lock = NSLock()
    private var destroyed = false

    convenience init(query: KeyQuery, target: GPGRunner, timeout: TimeInterval = 30,
                     run: @escaping Run = { try $0.run($1, allowingKeyLookup: true) }) throws {
        try self.init(entry: query.pseudoEntry, store: nil, target: target, timeout: timeout, manual: true, run: run)
    }

    init(entry: MissingKeyEntry, store: MissingKeyStore?, target: GPGRunner, timeout: TimeInterval = 30,
         manual: Bool = false, run: @escaping Run = { try $0.run($1, allowingKeyLookup: true) }) throws {
        self.entry = entry
        self.isManual = manual
        self.store = store
        self.target = GPGRunner(gpgPath: target.gpgPath, homeDir: target.homeDir, timeout: timeout)
        self.home = try IsolatedGPGHome.make(copyingConfigFrom: target)
        self.temp = GPGRunner(gpgPath: target.gpgPath, homeDir: home.url, timeout: timeout)
        self.run = run
    }

    /// Kills the temporary home's agent and dirmngr and deletes it; safe to call repeatedly.
    func destroy() {
        lock.lock()
        let already = destroyed
        destroyed = true
        lock.unlock()
        if !already { home.destroy(using: temp) }
    }

    var isDestroyed: Bool { lock.lock(); defer { lock.unlock() }; return destroyed }

    // MARK: Search

    func search() -> KeySearchResult {
        var errors: [String] = []
        var problems: [SearchProblem] = []
        let email = entry.senderEmail
        func attempt(_ arguments: [String], source: String) -> GPGProcessResult? {
            func record(_ detail: String) {
                errors.append("gpg \(arguments.first ?? ""): \(detail)")
                // One problem per source; a later failure of the same source (recv-keys) adds nothing new.
                if !problems.contains(where: { $0.source == source }) {
                    problems.append(SearchDiagnostics.classify(source: source, details: detail, email: email))
                }
            }
            do {
                let result = try run(temp, arguments)
                if result.exitCode != 0 {
                    let lines = SearchDiagnostics.cleanedLines(Bytes.string([UInt8](result.stderr)))
                    record(lines.isEmpty ? "exit code \(result.exitCode)" : lines.suffix(4).joined(separator: "; "))
                }
                return result
            } catch {
                record((error as? LocalizedError)?.errorDescription ?? "\(error)")
                return nil
            }
        }

        var found: [[KeyCandidate]] = []
        // (a) the user's auto-key-locate configuration (WKD, ...), into the temporary home.
        if let email = entry.senderEmail {
            _ = attempt(["--locate-external-keys", "--", email], source: SearchProblem.wkd)
            found.append(tempCandidates(source: KeyCandidate.locateSource))
        }
        // (b) the keyserver listing, never imported.
        let query = entry.senderEmail ?? entry.fingerprint ?? entry.keyID
        let searchTerm = entry.senderEmail == nil ? "0x" + query : query
        if let result = attempt(["--search-keys", "--", searchTerm], source: SearchProblem.keyserver) {
            let hits = KeyServerSearchParser.parse(Bytes.string([UInt8](result.stdout)))
            found.append(hits.map { KeyCandidate.make($0, entry: entry) })
        }
        var candidates = KeyCandidate.merge(found)
        // (c) last resort: fetch the signing key itself.
        if candidates.isEmpty {
            _ = attempt(["--recv-keys", "--", entry.fingerprint ?? entry.keyID], source: SearchProblem.keyserver)
            candidates = KeyCandidate.merge([tempCandidates(source: "recv-keys")])
        }
        // Signing key first, then keys with an email user ID, then the rest.
        candidates.sort { ($0.matchesSignature ? 0 : 1, $0.hasEmailUserID ? 0 : 1) < ($1.matchesSignature ? 0 : 1, $1.hasEmailUserID ? 0 : 1) }
        markManualAndKeyring(&candidates)
        let message = candidates.isEmpty
            ? (errors.isEmpty ? "No key was found." : errors.joined(separator: "\n")) : nil
        return KeySearchResult(token: token, candidates: candidates, message: message,
                               problems: candidates.isEmpty ? problems : [])
    }

    /// For a manual search the "matches the signature" flag means "matches the query"; also marks keys that the
    /// user's keyring already has.
    private func markManualAndKeyring(_ candidates: inout [KeyCandidate]) {
        let have = (try? KeyFetcherSupport.listAllUserIDs(target, fingerprints: [])) ?? []
        let fingerprints = Set(have.map { $0.fingerprint.uppercased() })
        let keyIDs = Set(have.map { $0.keyID.uppercased() })
        for index in candidates.indices {
            var candidate = candidates[index]
            if isManual {
                candidate.matchesQuery = candidate.matchesSignature
                candidate.matchesSignature = false
            }
            candidate.alreadyInKeyring = candidate.fingerprint.count == 16
                ? keyIDs.contains(candidate.fingerprint) : fingerprints.contains(candidate.fingerprint)
            candidates[index] = candidate
        }
        if isManual {
            candidates.sort { ($0.matchesQuery ? 0 : 1, $0.hasEmailUserID ? 0 : 1) < ($1.matchesQuery ? 0 : 1, $1.hasEmailUserID ? 0 : 1) }
        }
    }

    private func tempCandidates(source: String) -> [KeyCandidate] {
        ((try? KeyFetcherSupport.listAllUserIDs(temp, fingerprints: [])) ?? [])
            .map { KeyCandidate.make($0, source: source, entry: entry) }
    }

    // MARK: Import

    /// Imports the key with this fingerprint (or key ID, for a keyserver hit that carried no fingerprint) into the
    /// user's keyring. Requires an email user ID. Removes the missing-keys entry only if the key matches the
    /// signature.
    func importKey(fingerprint requested: String) throws -> KeyImportResult {
        guard let wanted = MissingKeyEntry.normalizedHex(requested), [16, 40, 64].contains(wanted.count) else {
            throw KeyFetchError("invalid fingerprint \(requested)")
        }
        func lookup() -> KeyInfo? {
            ((try? KeyFetcherSupport.listAllUserIDs(temp, fingerprints: [])) ?? []).first {
                wanted.count == 16 ? $0.keyID.uppercased() == wanted : $0.fingerprint.uppercased() == wanted
            }
        }
        var key = lookup()
        if key == nil {
            do {
                _ = try run(temp, ["--recv-keys", "--", wanted])
            } catch GPGError.timedOut {
                throw KeyFetchError("network error: gpg timed out")
            }
            key = lookup()
        }
        guard let key else { throw KeyFetchError("gpg could not retrieve the key \(Fingerprint.grouped(wanted)).") }
        guard key.userIDs.contains(where: { $0.email != nil }) else {
            throw KeyFetchError("the key \(Fingerprint.grouped(key.fingerprint)) has no user ID with an email address, "
                                + "so Sigil cannot use it")
        }
        try KeyFetcherSupport.transfer(key.fingerprint.uppercased(), from: temp, to: target)
        let matches = !isManual && MissingKeyMatch.matches(key, entry)
        var removed = false
        if matches, let store {
            try store.remove(id: entry.id)
            removed = true
        }
        return KeyImportResult(fingerprint: key.fingerprint.uppercased(), userIDs: key.userIDs.map(\.uid),
                               matchesSignature: matches, entryRemoved: removed)
    }
}

enum KeyFetcherSupport {
    /// Lists keys, including user IDs without an email (unlike `GPGRunner.listKeys`); no fingerprints lists all.
    static func listAllUserIDs(_ runner: GPGRunner, fingerprints: [String]) throws -> [KeyInfo] {
        let r = try runner.run(["--fixed-list-mode", "--with-fingerprint", "--with-subkey-fingerprint",
                                "--list-keys", "--"] + fingerprints)
        return GPGColonsParser.parseKeys(Bytes.string([UInt8](r.stdout)))
    }

    /// Fingerprints from `IMPORT_OK <reason> <fingerprint>` status lines (also reported for unchanged keys).
    static func importedFingerprints(_ result: GPGProcessResult) -> [String] {
        var fingerprints: [String] = []
        for line in result.status where line.keyword == "IMPORT_OK" && line.args.count >= 2 {
            if !fingerprints.contains(line.args[1]) { fingerprints.append(line.args[1]) }
        }
        return fingerprints
    }

    /// Exports exactly one key (by full fingerprint) from `source` and imports it into `target`.
    static func transfer(_ fingerprint: String, from source: GPGRunner, to target: GPGRunner) throws {
        guard MissingKeyEntry.normalizedHex(fingerprint) == fingerprint else {
            throw KeyFetchError("invalid fingerprint \(fingerprint)")
        }
        let export = try source.run(["--export", "--", fingerprint])
        guard export.exitCode == 0, !export.stdout.isEmpty else {
            throw KeyFetchError("could not export the key from the temporary keyring (\(export.diagnostics))")
        }
        let imported = try target.run(["--import-options", GPGRunner.importOptions, "--import"], stdin: export.stdout)
        guard imported.exitCode == 0, importedFingerprints(imported).contains(fingerprint) else {
            throw KeyFetchError("could not import the key into your keyring (\(imported.diagnostics))")
        }
    }
}

/// Keeps search sessions (temporary GnuPG homes) alive for a short time so the user can pick keys, then removes them.
final class KeySearchSessions: @unchecked Sendable {
    let lifetime: TimeInterval
    private let lock = NSLock()
    private var sessions: [String: KeySearchSession] = [:]

    init(lifetime: TimeInterval = 300) { self.lifetime = lifetime }

    func add(_ session: KeySearchSession) {
        lock.lock()
        sessions[session.token] = session
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + lifetime) { [weak self] in self?.discard(session.token) }
    }

    func session(_ token: String) -> KeySearchSession? {
        lock.lock(); defer { lock.unlock() }
        return sessions[token]
    }

    func discard(_ token: String) {
        lock.lock()
        let session = sessions.removeValue(forKey: token)
        lock.unlock()
        session?.destroy()
    }
}
