import Foundation

/// The XPC-exported implementation of `GPGServiceProtocol`. The helper only needs to export an instance.
public final class GPGService: NSObject, GPGServiceProtocol, Sendable {
    /// Deadlines for one decode inside the helper; when one passes, gpg is killed and the decode reports an error.
    public static let decodeDeadline: TimeInterval = 20
    public static let interactiveDecodeDeadline: TimeInterval = 140

    public let runner: (any GPGRunning)?
    /// Why `runner` is nil (gpg missing or rejected), reported by every call.
    public let runnerError: GPGError?
    /// Who is calling through this service's connection; decides which methods are allowed.
    public let caller: XPCCaller
    /// The helper's own settings (gpg path); nil disables `setGPGPath`.
    public let settings: HelperSettings?
    /// Kills the gpg runs of this service (the helper cancels it when the client connection goes away).
    public let cancellation = GPGCancellation()
    /// Records unknown signing keys after decodes; nil disables the missing-keys feature.
    public let missingKeys: MissingKeyRecorder?
    let searches = KeySearchSessions()
    /// The user's preferred encryption key per address; nil disables preferences.
    public let preferredKeys: PreferredKeyStore?

    public init(runner: (any GPGRunning)?, missingKeys: MissingKeyRecorder? = nil,
                preferredKeys: PreferredKeyStore? = nil, caller: XPCCaller = .app, settings: HelperSettings? = nil,
                runnerError: GPGError? = nil) {
        self.runner = runner
        self.runnerError = runnerError
        self.caller = caller
        self.settings = settings
        self.missingKeys = missingKeys
        self.preferredKeys = preferredKeys
        super.init()
    }

    /// Locates gpg (see `GPGRunner.locateGPG`) and creates a service on top of it. If gpg cannot be found,
    /// every call replies with an error.
    public convenience init(preferredGPGPath: String? = nil, homeDir: URL? = nil, timeout: TimeInterval = 120) {
        let runner = GPGRunner.locateGPG(preferred: preferredGPGPath).map {
            GPGRunner(gpgPath: $0, homeDir: homeDir, timeout: timeout)
        }
        self.init(runner: runner)
    }

    private func requireRunner(deadline: Date? = nil) throws -> any GPGRunning {
        guard let runner else { throw runnerError ?? GPGError.gpgNotFound }
        return runner.limited(deadline: deadline, cancellation: cancellation)
    }

    /// Stops every running gpg of this service; later calls fail with `GPGError.cancelled`.
    public func cancelAll() {
        cancellation.cancel()
    }

    /// The error text when the caller may not use `method`, else nil.
    private func denial(_ method: ServiceMethod) -> String? {
        ServiceAuthorization.isAllowed(method, for: caller) ? nil : "Sigil's Mail extension may not call \(method.rawValue)."
    }

    private static func message(_ error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? String(describing: error)
    }

    private static func json<T: Encodable>(_ value: T) throws -> Data {
        try SigilJSON.encoder().encode(value)
    }

    // MARK: - GPGServiceProtocol

    public func ping(reply: @escaping (String) -> Void) {
        if let denied = denial(.ping) { return reply("error: " + denied) }
        do {
            reply(try requireRunner().version())
        } catch {
            reply("error: " + GPGService.message(error))
        }
    }

    public func listKeys(secret: Bool, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.listKeys) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try requireRunner().listKeys(secret: secret, patterns: [])), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func encodingStatus(from: String, recipients: [String], reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.encodingStatus) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try encodingStatus(from: from, recipients: recipients)), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func encode(message: Data, sign: Bool, encrypt: Bool, from: String, recipients: [String],
                       hiddenRecipients: [String], reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.encode) { return reply(nil, denied) }
        do {
            reply(try encode(message: message, sign: sign, encrypt: encrypt, from: from,
                             recipients: recipients, hiddenRecipients: hiddenRecipients), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func decode(message: Data, interactive: Bool, allowMixed: Bool, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.decode) { return reply(nil, denied) }
        do {
            let deadline = Date() + (interactive ? GPGService.interactiveDecodeDeadline : GPGService.decodeDeadline)
            guard let outcome = PGPMIMEDecoder.decode(message: message, gpg: try requireRunner(deadline: deadline),
                                                      interactive: interactive, allowMixed: allowMixed) else {
                reply(nil, nil)
                return
            }
            missingKeys?.record(outcome: outcome, message: message)
            reply(try GPGService.json(outcome), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func pinentryStatus(reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.pinentryStatus) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try pinentryStatus()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func fixPinentry(reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.fixPinentry) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try fixPinentry()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func keyserverStatus(reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.keyserverStatus) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try keyserverStatus()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func fixKeyserver(reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.fixKeyserver) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try fixKeyserver()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func listMissingKeys(reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.listMissingKeys) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try requireMissingKeys().store.entries()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func dismissMissingKey(id: String, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.dismissMissingKey) { return reply(nil, denied) }
        setMissingKey(id: id, dismissed: true, reply: reply)
    }

    public func restoreMissingKey(id: String, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.restoreMissingKey) { return reply(nil, denied) }
        setMissingKey(id: id, dismissed: false, reply: reply)
    }

    public func removeMissingKey(id: String, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.removeMissingKey) { return reply(nil, denied) }
        do {
            let store = try requireMissingKeys().store
            guard try store.removeDismissed(id: id) else { throw KeyFetchError("No dismissed missing key \(id).") }
            reply(try GPGService.json(store.entries()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func removeDismissedMissingKeys(reply: @escaping (Int, String?) -> Void) {
        if let denied = denial(.removeDismissedMissingKeys) { return reply(0, denied) }
        do {
            reply(try requireMissingKeys().store.removeAllDismissed(), nil)
        } catch {
            reply(0, GPGService.message(error))
        }
    }

    private func setMissingKey(id: String, dismissed: Bool, reply: @escaping (Data?, String?) -> Void) {
        do {
            let store = try requireMissingKeys().store
            guard try store.setDismissed(id: id, dismissed) else { throw KeyFetchError("No missing key \(id).") }
            reply(try GPGService.json(store.entries()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func searchMissingKey(id: String, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.searchMissingKey) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try searchMissingKey(id: id)), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func searchKeys(query: String, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.searchKeys) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try searchKeys(query: query)), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func importCandidateKey(token: String, fingerprint: String, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.importCandidateKey) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try importCandidateKey(token: token, fingerprint: fingerprint)), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func discardKeySearch(token: String, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.discardKeySearch) { return reply(nil, denied) }
        searches.discard(token)
        reply(nil, nil)
    }

    public func setGPGPath(_ path: String?, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.setGPGPath) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try setGPGPath(path)), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func gpgPathStatus(reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.gpgPathStatus) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(gpgPathStatus()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    // MARK: - Swift API

    public func gpgPathStatus() -> GPGPathStatus {
        GPGPathStatus(configuredPath: settings?.gpgPath(), activePath: (runner as? GPGRunner)?.gpgPath.path)
    }

    /// Stores the gpg path override in the helper's own settings after `GPGPathValidator` accepted it; nil or empty
    /// clears it. It applies to connections made afterwards (the app reconnects).
    public func setGPGPath(_ rawPath: String?) throws -> GPGPathStatus {
        guard let settings else { throw KeyFetchError("The helper settings are not available.") }
        let path = rawPath?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if path.isEmpty {
            try settings.setGPGPath(nil)
        } else {
            _ = try GPGPathValidator.validate(path)
            try settings.setGPGPath(path)
        }
        return gpgPathStatus()
    }

    private func requireMissingKeys() throws -> MissingKeyRecorder {
        guard let missingKeys else { throw KeyFetchError("The missing-keys list is not available (no App Group access).") }
        return missingKeys
    }

    /// Looks for the key of a missing-keys entry in a temporary GnuPG home (see `KeySearchSession`) and returns the
    /// candidates; the user's keyring is untouched. The temporary home stays for a few minutes (until
    /// `discardKeySearch`) so a chosen key can be imported without searching again.
    public func searchMissingKey(id: String) throws -> KeySearchResult {
        try searchMissingKey(id: id, makeSession: nil)
    }

    func searchMissingKey(id: String, makeSession: ((MissingKeyEntry, MissingKeyStore) throws -> KeySearchSession)?)
        throws -> KeySearchResult {
        let store = try requireMissingKeys().store
        guard let entry = store.entry(id: id) else { throw KeyFetchError("No missing key \(id).") }
        let session: KeySearchSession
        if let makeSession {
            session = try makeSession(entry, store)
        } else {
            guard let gpg = try requireRunner() as? GPGRunner else { throw GPGError.gpgNotFound }
            session = try KeySearchSession(entry: entry, store: store, target: gpg)
        }
        return run(session)
    }

    /// Manual search for an email address, a fingerprint or a 16-digit key ID, in the same temporary home flow as
    /// `searchMissingKey`. An invalid query is rejected without calling gpg.
    public func searchKeys(query text: String) throws -> KeySearchResult {
        try searchKeys(query: text, makeSession: nil)
    }

    func searchKeys(query text: String, makeSession: ((KeyQuery) throws -> KeySearchSession)?) throws -> KeySearchResult {
        guard let query = KeyQuery.parse(text) else {
            throw KeyFetchError("Enter an email address, a fingerprint (40 or 64 hex digits) or a 16-digit key ID.")
        }
        if let makeSession { return run(try makeSession(query)) }
        guard let gpg = try requireRunner() as? GPGRunner else { throw GPGError.gpgNotFound }
        return run(try KeySearchSession(query: query, target: gpg))
    }

    private func run(_ session: KeySearchSession) -> KeySearchResult {
        let result = session.search()
        if result.candidates.isEmpty {
            session.destroy()
        } else {
            searches.add(session)
        }
        return result
    }

    public func importCandidateKey(token: String, fingerprint: String) throws -> KeyImportResult {
        guard let session = searches.session(token) else {
            throw KeyFetchError("The key search has expired. Search again.")
        }
        return try session.importKey(fingerprint: fingerprint)
    }

    func hasSearchSession(_ token: String) -> Bool { searches.session(token) != nil }

    public func pinentryStatus() throws -> PinentryStatus {
        GPGAgentConfig.status(configURL: try requireRunner().agentConfigURL())
    }

    /// Sets `pinentry-program` to the installed pinentry-mac (never a caller-supplied path), commenting out
    /// earlier settings, and reloads gpg-agent.
    public func fixPinentry() throws -> PinentryStatus {
        let gpg = try requireRunner()
        let configURL = try gpg.agentConfigURL()
        guard let pinentryMac = GPGAgentConfig.locatePinentryMac() else {
            throw GPGError.operationFailed("pinentry-mac is not installed (brew install pinentry-mac)")
        }
        let current = GPGAgentConfig.status(configURL: configURL)
        if current.pinentryProgram == pinentryMac { return current }
        let text = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        try Data(GPGAgentConfig.settingPinentryProgram(pinentryMac, in: text).utf8).write(to: configURL)
        try gpg.reloadAgent()
        return GPGAgentConfig.status(configURL: configURL)
    }

    public func keyserverStatus() throws -> KeyserverStatus {
        let gpg = try requireRunner()
        return DirmngrConfig.status(configURL: try gpg.dirmngrConfigURL(), keyserver: try gpg.configuredKeyserver())
    }

    /// Appends `keyserver hkps://keys.openpgp.org` to dirmngr.conf (never a caller-supplied URL), commenting out
    /// a `keyserver` line that points to none, and reloads dirmngr. Does nothing if a keyserver is configured.
    public func fixKeyserver() throws -> KeyserverStatus {
        let gpg = try requireRunner()
        let configURL = try gpg.dirmngrConfigURL()
        let current = DirmngrConfig.status(configURL: configURL, keyserver: try gpg.configuredKeyserver())
        if current.isConfigured { return current }
        let text = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        try Data(DirmngrConfig.addingKeyserver(to: text).utf8).write(to: configURL)
        try gpg.reloadDirmngr()
        return DirmngrConfig.status(configURL: configURL, keyserver: try gpg.configuredKeyserver())
    }

    public func encodingStatus(from: String, recipients: [String]) throws -> EncodingStatus {
        let signer = try resolveSigner(from: from)
        var missing: [String] = []
        var unverified: [String] = []
        var ambiguous: [String] = []
        for recipient in recipients {
            switch try resolveRecipientKey(recipient) {
            case .missing: missing.append(recipient)
            case .ambiguous: ambiguous.append(recipient)
            case let .key(key):
                if !GPGService.isVerified(key, for: EmailAddress.parse(recipient).email ?? "") { unverified.append(recipient) }
            }
        }
        return EncodingStatus(canSign: signer != nil, signerFingerprint: signer?.fingerprint,
                              missingRecipients: missing, canEncrypt: !recipients.isEmpty && missing.isEmpty,
                              unverifiedRecipients: unverified, ambiguousRecipients: ambiguous)
    }

    public func encode(message: Data, sign: Bool, encrypt: Bool, from: String, recipients: [String],
                       hiddenRecipients: [String]) throws -> Data {
        let gpg = try requireRunner()
        guard sign || encrypt else { return message }

        var signer: KeyInfo? = nil
        if sign {
            guard let s = try resolveSigner(from: from) else {
                throw GPGError.missingKeys(["secret key for \(EmailAddress.extract(from))"])
            }
            signer = s
        }
        guard encrypt else {
            return try PGPMIMEEncoder.sign(message: message, signer: signer!.fingerprint, gpg: gpg)
        }

        var missing: [String] = []
        var ambiguous: [String] = []
        var visible: [String] = []
        var hidden: [String] = []
        func key(for recipient: String) throws -> KeyInfo? {
            switch try resolveRecipientKey(recipient) {
            case let .key(key): return key
            case .missing: missing.append(recipient)
            case .ambiguous: ambiguous.append(EmailAddress.extract(recipient))
            }
            return nil
        }
        for r in recipients {
            if let k = try key(for: r), !visible.contains(k.fingerprint) { visible.append(k.fingerprint) }
        }
        for r in hiddenRecipients {
            if let k = try key(for: r), !visible.contains(k.fingerprint) && !hidden.contains(k.fingerprint) {
                hidden.append(k.fingerprint)
            }
        }
        guard missing.isEmpty else { throw GPGError.missingKeys(missing) }
        guard ambiguous.isEmpty else { throw GPGError.ambiguousRecipients(ambiguous) }
        guard !(visible.isEmpty && hidden.isEmpty) else { throw GPGError.noRecipients }

        // Encrypt to self so the sender can read the sent copy (never to a guessed key of the sender either).
        if let s = signer, s.capabilities.encrypt {
            if !visible.contains(s.fingerprint) { visible.append(s.fingerprint) }
        } else {
            switch try resolveRecipientKey(from) {
            case let .key(me): if !visible.contains(me.fingerprint) { visible.append(me.fingerprint) }
            case .ambiguous: throw GPGError.ambiguousRecipients([EmailAddress.extract(from)])
            case .missing: break
            }
        }
        return try PGPMIMEEncoder.encrypt(message: message, recipients: visible, hidden: hidden,
                                          signer: signer?.fingerprint, gpg: gpg)
    }

    /// A usable secret signing key with a user ID matching the sender address.
    /// Matching goes only through email user IDs (case-insensitive address comparison; listings drop keys and
    /// user IDs without an email), never through fingerprints or names.
    public func resolveSigner(from: String) throws -> KeyInfo? {
        guard let email = EmailAddress.parse(from).email else { return nil }
        let keys = try requireRunner().listKeys(secret: true, patterns: ["<\(email)>"])
        return keys.first { k in
            k.isUsable && k.capabilities.sign
                && k.userIDs.contains { $0.email == email && !RecipientKeyChoice.unusableUIDValidities.contains($0.validity) }
        }
    }

    /// The one public encryption key used for a recipient address, chosen by `RecipientKeyChoice.resolve`: the
    /// preferred key for the address if it is still usable; nil when there is none or several unverified ones (never a
    /// guess); else a verified key over an unverified one, then the newest, then the lowest fingerprint. Validity below full is accepted (owner decision: encrypt to unverified keys, mark them in
    /// compose).
    public func resolveRecipient(_ recipient: String) throws -> KeyInfo? {
        try resolveRecipientKey(recipient).key
    }

    /// Like `resolveRecipient`, but tells a missing key from an ambiguous choice (`RecipientKeyChoice.resolve`).
    public func resolveRecipientKey(_ recipient: String) throws -> RecipientKeyResolution {
        guard let email = EmailAddress.parse(recipient).email else { return .missing }
        let keys = try requireRunner().listKeys(secret: false, patterns: ["<\(email)>"])
        return RecipientKeyChoice.resolve(from: keys, email: email, preferred: preferredKeys?.fingerprint(for: email))
    }

    // MARK: - Preferred keys

    public func listPreferredKeys(reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.listPreferredKeys) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try listPreferredKeys()), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    public func setPreferredKey(email: String, fingerprint: String?, reply: @escaping (Data?, String?) -> Void) {
        if let denied = denial(.setPreferredKey) { return reply(nil, denied) }
        do {
            reply(try GPGService.json(try setPreferredKey(email: email, fingerprint: fingerprint)), nil)
        } catch {
            reply(nil, GPGService.message(error))
        }
    }

    /// All stored preferences; `usable` is false for one whose key is gone, expired, revoked or lacks the address
    /// (such a preference is ignored when choosing keys).
    public func listPreferredKeys() throws -> [PreferredKeyEntry] {
        guard let preferredKeys else { throw KeyFetchError("Preferred keys are not available (no App Group access).") }
        let gpg = try requireRunner()
        return preferredKeys.all().map { email, fingerprint in
            let keys = (try? gpg.listKeys(secret: false, patterns: ["<\(email)>"])) ?? []
            let usable = keys.contains { $0.fingerprint.uppercased() == fingerprint
                && RecipientKeyChoice.isUsableEncryptionKey($0, for: email) }
            return PreferredKeyEntry(email: email, fingerprint: fingerprint, usable: usable)
        }.sorted { $0.email < $1.email }
    }

    /// Sets (or, with a nil fingerprint, clears) the preferred key for an address. The key must currently be a
    /// usable encryption key for that address.
    public func setPreferredKey(email rawEmail: String, fingerprint: String?) throws -> [PreferredKeyEntry] {
        guard let preferredKeys else { throw KeyFetchError("Preferred keys are not available (no App Group access).") }
        guard let email = EmailAddress.parse(rawEmail).email else { throw KeyFetchError("Invalid address \(rawEmail).") }
        if let fingerprint {
            let wanted = fingerprint.uppercased()
            let keys = try requireRunner().listKeys(secret: false, patterns: ["<\(email)>"])
            guard keys.contains(where: { $0.fingerprint.uppercased() == wanted
                && RecipientKeyChoice.isUsableEncryptionKey($0, for: email) }) else {
                throw KeyFetchError("The key \(Fingerprint.grouped(wanted)) is not a usable encryption key for \(email).")
            }
            try preferredKeys.set(email: email, fingerprint: wanted)
        } else {
            try preferredKeys.set(email: email, fingerprint: nil)
        }
        return try listPreferredKeys()
    }

    /// True when a user ID of `key` matching `email` is fully or ultimately valid.
    static func isVerified(_ key: KeyInfo, for email: String) -> Bool {
        RecipientKeyChoice.isVerified(key, for: email)
    }
}
