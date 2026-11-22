import Foundation
import os
import SigilCore

/// XPC client for SigilHelper, shared by the app and the Mail extension.
///
/// The connection is created lazily and dropped when it is invalidated (for example when the helper is not
/// registered or the peer check fails), so the next call reconnects. An interrupted connection (helper crashed or
/// was restarted) stays usable: launchd starts the helper again on the next message.
final class HelperClient: @unchecked Sendable {
    static let shared = HelperClient()

    enum ClientError: LocalizedError {
        case notConfigured
        case unavailable(String)
        case timedOut
        case helper(String)
        case invalidReply

        var errorDescription: String? {
            switch self {
            case .notConfigured: return "The helper connection is not configured (Info.plist or code signature incomplete)."
            case let .unavailable(reason): return "The Sigil helper is not reachable (\(reason))."
            case .timedOut: return "The Sigil helper did not answer in time."
            case let .helper(message): return message
            case .invalidReply: return "The Sigil helper sent an invalid reply."
            }
        }
    }

    let machServiceName: String?
    let timeout: TimeInterval

    private let logger = Logger(subsystem: "org.fuchss.sigil", category: "client")
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    init(machServiceName: String? = Bundle.main.object(forInfoDictionaryKey: "SigilMachServiceName") as? String,
         timeout: TimeInterval = 30) {
        self.machServiceName = machServiceName
        self.timeout = timeout
    }

    // MARK: - Typed calls

    func ping() async throws -> String {
        let version: String = try await call { proxy, done in proxy.ping { done(.success($0)) } }
        if version.hasPrefix("error: ") { throw ClientError.helper(String(version.dropFirst("error: ".count))) }
        return version
    }

    func listKeys(secret: Bool) async throws -> [KeyInfo] {
        try await callJSON { proxy, reply in proxy.listKeys(secret: secret, reply: reply) }
    }

    func encodingStatus(from: String, recipients: [String]) async throws -> EncodingStatus {
        try await callJSON { proxy, reply in proxy.encodingStatus(from: from, recipients: recipients, reply: reply) }
    }

    func pinentryStatus() async throws -> PinentryStatus {
        try await callJSON { proxy, reply in proxy.pinentryStatus(reply: reply) }
    }

    func fixPinentry() async throws -> PinentryStatus {
        try await callJSON { proxy, reply in proxy.fixPinentry(reply: reply) }
    }

    func keyserverStatus() async throws -> KeyserverStatus {
        try await callJSON { proxy, reply in proxy.keyserverStatus(reply: reply) }
    }

    func fixKeyserver() async throws -> KeyserverStatus {
        try await callJSON { proxy, reply in proxy.fixKeyserver(reply: reply) }
    }

    func listMissingKeys() async throws -> [MissingKeyEntry] {
        try await callJSON { proxy, reply in proxy.listMissingKeys(reply: reply) }
    }

    func setMissingKey(id: String, dismissed: Bool) async throws -> [MissingKeyEntry] {
        try await callJSON { proxy, reply in
            if dismissed { proxy.dismissMissingKey(id: id, reply: reply) } else { proxy.restoreMissingKey(id: id, reply: reply) }
        }
    }

    func removeMissingKey(id: String) async throws -> [MissingKeyEntry] {
        try await callJSON { proxy, reply in proxy.removeMissingKey(id: id, reply: reply) }
    }

    func removeDismissedMissingKeys() async throws -> Int {
        try await callJSON { proxy, reply in
            proxy.removeDismissedMissingKeys { count, error in
                reply(error == nil ? Data(String(count).utf8) : nil, error)
            }
        }
    }

    /// Budget for a key search: the helper runs up to four gpg commands of at most 30 s each.
    static let searchTimeout: TimeInterval = 150
    /// Budget for an import: the helper may first retrieve the key (30 s), then export and import it.
    static let importTimeout: TimeInterval = 75

    func searchMissingKey(id: String) async throws -> KeySearchResult {
        try await callJSON(timeout: HelperClient.searchTimeout) { proxy, reply in proxy.searchMissingKey(id: id, reply: reply) }
    }

    func searchKeys(query: String) async throws -> KeySearchResult {
        try await callJSON(timeout: HelperClient.searchTimeout) { proxy, reply in proxy.searchKeys(query: query, reply: reply) }
    }

    func importCandidateKey(token: String, fingerprint: String) async throws -> KeyImportResult {
        try await callJSON(timeout: HelperClient.importTimeout) { proxy, reply in
            proxy.importCandidateKey(token: token, fingerprint: fingerprint, reply: reply)
        }
    }

    /// Tells the helper to delete the temporary keyring of a search (it also does so by itself after a few minutes).
    func discardKeySearch(token: String) async throws {
        try await call { proxy, done in
            proxy.discardKeySearch(token: token) { _, error in
                done(error.map { .failure(ClientError.helper($0)) } ?? .success(()))
            }
        }
    }

    func listPreferredKeys() async throws -> [PreferredKeyEntry] {
        try await callJSON { proxy, reply in proxy.listPreferredKeys(reply: reply) }
    }

    func setPreferredKey(email: String, fingerprint: String?) async throws -> [PreferredKeyEntry] {
        try await callJSON { proxy, reply in proxy.setPreferredKey(email: email, fingerprint: fingerprint, reply: reply) }
    }

    /// Validated and stored by the helper (app only); nil or empty means automatic.
    func setGPGPath(_ path: String?) async throws -> GPGPathStatus {
        try await callJSON { proxy, reply in proxy.setGPGPath(path, reply: reply) }
    }

    func gpgPathStatus() async throws -> GPGPathStatus {
        try await callJSON { proxy, reply in proxy.gpgPathStatus(reply: reply) }
    }

    /// Drops the connection so the next call reconnects, and the helper builds a fresh service (for example after
    /// the gpg path setting changed).
    func reconnect() {
        lock.lock()
        let old = connection
        connection = nil
        lock.unlock()
        old?.invalidate()
    }

    /// Synchronous decode for `decodedMessage(forMessageData:)`, which MailKit calls synchronously (on the main
    /// thread). Blocking the calling thread is fine: XPC delivers the reply on its own queue. Nil means
    /// "not a PGP message".
    ///
    /// On a timeout the connection is dropped: the helper then kills the gpg it is still running for this client
    /// (besides its own decode deadline).
    func decodeSync(message: Data, interactive: Bool, timeout: TimeInterval? = nil) throws -> DecodeOutcome? {
        do {
            return try callSync(timeout: timeout) { proxy, done in
                proxy.decode(message: message, interactive: interactive, allowMixed: false) { data, error in
                    done(HelperClient.decodeOptional(data, error))
                }
            }
        } catch ClientError.timedOut {
            reconnect()
            throw ClientError.timedOut
        }
    }

    /// Asynchronous decode; with `interactive == true` gpg may show pinentry, so give it a long timeout.
    /// `allowMixed`: the user asked to decrypt encrypted parts mixed with other content; the result must only be shown
    /// in Sigil's own view, never returned to Mail as message content.
    func decode(message: Data, interactive: Bool, allowMixed: Bool = false, timeout: TimeInterval? = nil) async throws
        -> DecodeOutcome? {
        try await call(timeout: timeout) { proxy, done in
            proxy.decode(message: message, interactive: interactive, allowMixed: allowMixed) { data, error in
                done(HelperClient.decodeOptional(data, error))
            }
        }
    }

    /// Line endings of the encoded message handed back to Mail. The single switch for the sending path.
    ///
    /// The helper always produces CRLF and signs the CRLF-canonical body (RFC 3156), with every line ending in
    /// CRLF and no bare CR or LF, so converting between LF and CRLF is lossless and keeps the signature valid.
    /// `.matchInput` (default) returns the line endings Mail handed over: on macOS 27 that is LF, which is Mail's
    /// internal form (its decoder input is LF too, and CRLF given back to it renders blank); Mail converts to CRLF
    /// itself when it transmits over SMTP, as it does for every unsigned message.
    enum OutgoingLineEndings { case matchInput, crlf, lf }
    static let outgoingLineEndings: OutgoingLineEndings = .matchInput

    /// Budget for `encode`: signing may wait for the passphrase entry (the helper kills gpg after 120 s).
    static let encodeTimeout: TimeInterval = 150

    /// Signs and/or encrypts an outgoing message as the Mail extension does, returning it with the line endings
    /// chosen by `outgoingLineEndings`. Always interactive: gpg may show pinentry for the signing key.
    func encodeForMail(message: Data, sign: Bool, encrypt: Bool, from: String, recipients: [String],
                       hiddenRecipients: [String]) async throws -> Data {
        let encoded: Data = try await call(timeout: HelperClient.encodeTimeout) { proxy, done in
            proxy.encode(message: message, sign: sign, encrypt: encrypt, from: from, recipients: recipients,
                         hiddenRecipients: hiddenRecipients) { data, error in
                if let error { return done(.failure(ClientError.helper(error))) }
                guard let data, !data.isEmpty else { return done(.failure(ClientError.invalidReply)) }
                done(.success(data))
            }
        }
        switch HelperClient.outgoingLineEndings {
        case .matchInput: return LineEndings.usesBareLF(message) ? LineEndings.toLF(encoded) : encoded
        case .crlf: return LineEndings.toCRLF(encoded)
        case .lf: return LineEndings.toLF(encoded)
        }
    }

    // MARK: - Generic plumbing

    typealias Body<T> = (GPGServiceProtocol, @escaping (Result<T, Error>) -> Void) -> Void

    func call<T>(timeout: TimeInterval? = nil, _ body: @escaping Body<T>) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            perform(timeout: timeout ?? self.timeout, body) { continuation.resume(with: $0) }
        }
    }

    func callSync<T>(timeout: TimeInterval? = nil, _ body: @escaping Body<T>) throws -> T {
        let finished = DispatchSemaphore(value: 0)
        let box = ResultBox<T>()
        let limit = timeout ?? self.timeout
        perform(timeout: limit, body) { result in
            box.result = result
            finished.signal()
        }
        // perform() enforces the timeout itself; the extra second only guards against a lost reply.
        guard finished.wait(timeout: .now() + limit + 1) == .success, let result = box.result else {
            throw ClientError.timedOut
        }
        return try result.get()
    }

    private func callJSON<T: Decodable>(timeout: TimeInterval? = nil,
                                        _ body: @escaping (GPGServiceProtocol, @escaping (Data?, String?) -> Void) -> Void)
        async throws -> T {
        try await call(timeout: timeout) { proxy, done in
            body(proxy) { data, error in
                done(HelperClient.decodeOptional(data, error).flatMap { value in
                    value.map(Result.success) ?? .failure(ClientError.invalidReply)
                })
            }
        }
    }

    private static func decodeOptional<T: Decodable>(_ data: Data?, _ error: String?) -> Result<T?, Error> {
        if let error { return .failure(ClientError.helper(error)) }
        guard let data else { return .success(nil) }
        do {
            return .success(try SigilJSON.decoder().decode(T.self, from: data))
        } catch {
            return .failure(ClientError.invalidReply)
        }
    }

    /// Sends one message; `completion` runs exactly once: with the reply, the connection error, or a timeout.
    private func perform<T>(timeout: TimeInterval, _ body: Body<T>, completion: @escaping (Result<T, Error>) -> Void) {
        let once = OnceCompletion(completion)
        guard let connection = currentConnection() else {
            once.finish(.failure(ClientError.notConfigured))
            return
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            once.finish(.failure(ClientError.unavailable(error.localizedDescription)))
        }
        guard let service = proxy as? GPGServiceProtocol else {
            once.finish(.failure(ClientError.invalidReply))
            return
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            once.finish(.failure(ClientError.timedOut))
        }
        body(service) { once.finish($0) }
    }

    private func currentConnection() -> NSXPCConnection? {
        lock.lock()
        defer { lock.unlock() }
        if let connection { return connection }
        guard let machServiceName, !machServiceName.isEmpty, !machServiceName.contains("$(") else { return nil }

        // Only talk to our own helper: `<prefix>.helper`, signed by the team that signed this process.
        guard let prefix = SigilXPC.bundlePrefix, let teamID = SigilXPC.ownTeamIdentifier(), !teamID.isEmpty else {
            logger.error("cannot verify the helper: no bundle prefix or team identifier in the own signature")
            return nil
        }
        let newConnection = NSXPCConnection(machServiceName: machServiceName, options: [])
        newConnection.setCodeSigningRequirement(SigilXPC.helperRequirement(teamID: teamID, prefix: prefix))
        newConnection.remoteObjectInterface = SigilXPC.makeInterface()
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            self?.logger.info("helper connection invalidated")
            self?.drop(newConnection)
        }
        newConnection.interruptionHandler = { [weak self] in
            self?.logger.info("helper connection interrupted; will be re-established on the next call")
        }
        newConnection.resume()
        connection = newConnection
        return newConnection
    }

    private func drop(_ invalidated: NSXPCConnection?) {
        lock.lock()
        defer { lock.unlock() }
        if connection === invalidated { connection = nil }
    }
}

/// Runs a completion handler at most once, from whichever thread gets there first.
private final class OnceCompletion<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Result<T, Error>) -> Void)?

    init(_ completion: @escaping (Result<T, Error>) -> Void) {
        self.completion = completion
    }

    func finish(_ result: Result<T, Error>) {
        lock.lock()
        let pending = completion
        completion = nil
        lock.unlock()
        pending?(result)
    }
}

private final class ResultBox<T>: @unchecked Sendable {
    var result: Result<T, Error>?
}
