import Foundation

public struct InvalidKeySpec: Codable, Sendable, Equatable {
    public var reason: Int
    public var spec: String

    public init(reason: Int, spec: String) {
        self.reason = reason
        self.spec = spec
    }

    public var reasonText: String {
        switch reason {
        case 1: return "not found"
        case 2: return "ambiguous specification"
        case 3: return "wrong key usage"
        case 4: return "key revoked"
        case 5: return "key expired"
        case 6: return "no CRL known"
        case 7: return "CRL too old"
        case 8: return "policy mismatch"
        case 9: return "not a secret key"
        case 10: return "key not trusted"
        case 11: return "missing certificate"
        case 12: return "missing issuer certificate"
        case 13: return "key disabled"
        case 14: return "syntax error in specification"
        default: return "unusable key"
        }
    }
}

public enum GPGError: Error, Sendable, Equatable, LocalizedError {
    case gpgNotFound
    case launchFailed(String)
    case timedOut
    case noRecipients
    case invalidRecipients([InvalidKeySpec])
    case invalidSigner([InvalidKeySpec])
    case missingKeys([String])
    case noSecretKey([String])
    case needsPassphrase
    case decryptionFailed(String)
    case integrityCheckFailed
    case noSignatureFound
    case malformedMessage(String)
    case operationFailed(String)
    case outputTooLarge
    case deadlineExceeded
    case cancelled
    case unsupportedVersion(String)
    case ambiguousRecipients([String])
    case tooManyParts(Int)

    public var errorDescription: String? {
        switch self {
        case .gpgNotFound: return "GnuPG (gpg) was not found."
        case let .launchFailed(m): return "Could not launch gpg: \(m)"
        case .timedOut: return "gpg timed out."
        case .noRecipients: return "No recipients given."
        case let .invalidRecipients(r):
            return "Invalid recipients: " + r.map { "\($0.spec) (\($0.reasonText))" }.joined(separator: ", ")
        case let .invalidSigner(r):
            return "Invalid signing key: " + r.map { "\($0.spec) (\($0.reasonText))" }.joined(separator: ", ")
        case let .missingKeys(k): return "No usable key for: " + k.joined(separator: ", ")
        case let .noSecretKey(ids): return "No secret key available to decrypt (" + ids.joined(separator: ", ") + ")."
        case .needsPassphrase: return "A passphrase is required."
        case let .decryptionFailed(m): return "Decryption failed: \(m)"
        case .integrityCheckFailed: return "The message is not integrity protected or was modified; it was not decrypted."
        case .noSignatureFound: return "No signature found."
        case let .malformedMessage(m): return "Malformed message: \(m)"
        case let .operationFailed(m): return "gpg failed: \(m)"
        case .outputTooLarge: return "gpg produced more output than Sigil allows (a compressed message may be hiding a huge payload); it was stopped."
        case .deadlineExceeded: return "Checking this message took too long; Sigil stopped gpg."
        case .cancelled: return "The operation was cancelled."
        case let .unsupportedVersion(found): return "GnuPG 2.2.17 or newer required (found \(found))."
        case let .ambiguousRecipients(addresses):
            return addresses.map {
                "\($0) has several unverified keys. Choose one under Public Keys > Prefer for \($0) in the Sigil app."
            }.joined(separator: " ")
        case let .tooManyParts(count):
            return "This message has \(count) PGP parts; Sigil checks at most \(PGPMIMEDecoder.maxPGPParts) per message."
        }
    }
}

/// The gpg operations used by the encoder/decoder. `GPGRunner` is the real implementation;
/// tests may substitute their own.
public protocol GPGRunning: Sendable {
    func version() throws -> String
    func listKeys(secret: Bool, patterns: [String]) throws -> [KeyInfo]
    func sign(_ data: Data, signerFingerprint: String) throws -> (signature: Data, micalg: String)
    func encrypt(_ data: Data, recipients: [String], hiddenRecipients: [String], signerFingerprint: String?) throws -> Data
    /// Decrypts (and verifies) armored or binary OpenPGP data. With `interactive == false` gpg never asks for a
    /// passphrase (`--pinentry-mode error`): it only succeeds if no passphrase is needed or gpg-agent has it cached,
    /// and otherwise fails at once with `GPGError.needsPassphrase`.
    func decrypt(_ data: Data, interactive: Bool) throws -> DecryptResult
    func verify(_ data: Data, detachedSignature: Data) throws -> [SignatureResult]
    /// Verifies a cleartext-signed (or signed-only armored) message, returning the signed text.
    func verifyInline(_ data: Data) throws -> (plaintext: Data, signatures: [SignatureResult])
    /// Location of gpg-agent.conf in the GnuPG home directory (from `gpgconf --list-dirs homedir`).
    func agentConfigURL() throws -> URL
    /// Makes a running gpg-agent re-read its configuration (`gpgconf --reload gpg-agent`).
    func reloadAgent() throws
    /// Location of dirmngr.conf in the GnuPG home directory.
    func dirmngrConfigURL() throws -> URL
    /// The effective keyserver of dirmngr (`gpgconf --list-options dirmngr`); nil when none is configured.
    func configuredKeyserver() throws -> String?
    /// Makes a running dirmngr re-read its configuration (`gpgconf --reload dirmngr`).
    func reloadDirmngr() throws
    /// A runner whose gpg calls end at `deadline` and when `cancellation` fires. Test doubles may return themselves.
    func limited(deadline: Date?, cancellation: GPGCancellation?) -> any GPGRunning
}

public extension GPGRunning {
    func limited(deadline: Date?, cancellation: GPGCancellation?) -> any GPGRunning { self }
    func listKeys(secret: Bool) throws -> [KeyInfo] { try listKeys(secret: secret, patterns: []) }
    /// Decrypts with gpg's default pinentry behaviour (may ask for a passphrase).
    func decrypt(_ data: Data) throws -> DecryptResult { try decrypt(data, interactive: true) }
}

public struct GPGProcessResult: Sendable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data
    public let status: [GPGStatusLine]

    /// Human-readable diagnostic lines from stderr (never contains plaintext).
    public var diagnostics: String {
        let lines = Bytes.string([UInt8](stderr)).split(separator: "\n")
            .filter { $0.hasPrefix("gpg: ") }
            .map { String($0.dropFirst(5)) }
        return lines.suffix(4).joined(separator: "; ")
    }

    public func has(_ keyword: String) -> Bool { status.contains { $0.keyword == keyword } }
}

/// Runs gpg as a subprocess. Immutable and safe to share between threads.
public final class GPGRunner: GPGRunning, Sendable {
    public let gpgPath: URL
    public let homeDir: URL?
    public let timeout: TimeInterval
    /// Caps on what one gpg run may write; above them gpg is killed (`GPGError.outputTooLarge`).
    public let maxStdout: Int
    public let maxStderr: Int
    public let maxStatus: Int
    /// No run continues past this point in time (`GPGError.deadlineExceeded`).
    public let deadline: Date?
    /// Kills the running gpg when cancelled (`GPGError.cancelled`).
    public let cancellation: GPGCancellation?

    public static let defaultMaxStdout = 64 * 1024 * 1024
    public static let defaultMaxStderr = 1024 * 1024
    public static let defaultMaxStatus = 4 * 1024 * 1024

    public init(gpgPath: URL, homeDir: URL? = nil, timeout: TimeInterval = 60,
                maxStdout: Int = GPGRunner.defaultMaxStdout, maxStderr: Int = GPGRunner.defaultMaxStderr,
                maxStatus: Int = GPGRunner.defaultMaxStatus, deadline: Date? = nil, cancellation: GPGCancellation? = nil) {
        self.gpgPath = gpgPath
        self.homeDir = homeDir
        self.timeout = timeout
        self.maxStdout = maxStdout
        self.maxStderr = maxStderr
        self.maxStatus = maxStatus
        self.deadline = deadline
        self.cancellation = cancellation
    }

    public func limited(deadline: Date?, cancellation: GPGCancellation?) -> any GPGRunning {
        GPGRunner(gpgPath: gpgPath, homeDir: homeDir, timeout: timeout, maxStdout: maxStdout, maxStderr: maxStderr,
                  maxStatus: maxStatus, deadline: deadline ?? self.deadline, cancellation: cancellation ?? self.cancellation)
    }

    /// Default install locations, tried in this order when no path is configured.
    public static let defaultCandidates = ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/local/MacGPG2/bin/gpg"]

    /// The first gpg among `preferred` and the default locations that passes `GPGPathValidator` (an absolute
    /// path to a regular executable owned by the user or root, not group/world-writable, outside temporary and
    /// container directories, that reports itself as GnuPG 2.2.17 or newer, with a gpgconf next to it).
    public static func locateGPG(preferred: String? = nil) -> URL? {
        var candidates: [String] = []
        if let p = preferred, !p.isEmpty { candidates.append(p) }
        candidates += defaultCandidates
        return candidates.lazy.compactMap { try? GPGPathValidator.validate($0) }.first
    }

    var baseArguments: [String] { baseArguments(allowingKeyLookup: false) }

    /// Used for every import of a fetched key (into the temporary home and into the user's keyring).
    static let importOptions = "import-clean,self-sigs-only"

    /// Without `allowingKeyLookup` gpg never goes to the network (no auto-key-locate/-retrieve), which is how every
    /// decode and verify runs. Only an explicit key fetch drops the two options, so gpg then uses the user's own
    /// gpg.conf (`auto-key-locate`) and dirmngr (keyserver) configuration.
    func baseArguments(allowingKeyLookup: Bool) -> [String] {
        var a = ["--batch", "--no-tty", "--status-fd", "3", "--with-colons", "--no-verbose",
                 "--display-charset", "utf-8"]
        if allowingKeyLookup {
            // Keys fetched from the network keep only their self-signatures (no certificate flooding) and lose
            // unusable parts.
            a += ["--import-options", GPGRunner.importOptions]
        } else {
            a += ["--no-auto-key-locate", "--no-auto-key-retrieve"]
        }
        if let homeDir { a = ["--homedir", homeDir.path] + a }
        return a
    }

    // MARK: - Process execution

    /// Runs gpg with the given arguments (appended to the base arguments), feeding `stdin`.
    ///
    /// gpg writes its `[GNUPG:]` status lines to a dedicated pipe (fd 3 in the child), never mixed with stderr, so
    /// nothing gpg prints as a diagnostic (user IDs, file names) can be mistaken for a status line. stdout and stderr
    /// are read with hard caps (`maxStdout`, `maxStderr`): above them gpg is killed and `GPGError.outputTooLarge`
    /// thrown (a compressed literal can expand to gigabytes). The run also ends at the runner's `deadline` and when its
    /// `cancellation` fires.
    public func run(_ arguments: [String], stdin: Data? = nil, allowingKeyLookup: Bool = false) throws -> GPGProcessResult {
        if cancellation?.isCancelled == true { throw GPGError.cancelled }
        var limit = timeout
        var limitedByDeadline = false
        if let deadline {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { throw GPGError.deadlineExceeded }
            if remaining < limit { limit = remaining; limitedByDeadline = true }
        }
        var env = ProcessInfo.processInfo.environment
        env["LC_ALL"] = nil
        env["LC_MESSAGES"] = "C"
        env["LANGUAGE"] = "C"

        let child: SpawnedChild
        do {
            child = try SpawnedChild.spawn(path: gpgPath.path,
                                           arguments: baseArguments(allowingKeyLookup: allowingKeyLookup) + arguments,
                                           environment: env)
        } catch {
            throw GPGError.launchFailed(error.localizedDescription)
        }
        let pid = child.pid
        let registered = cancellation?.register(pid) ?? true
        if !registered { kill(pid, SIGKILL) }

        let overflow = OverflowFlag()
        let killChild: @Sendable () -> Void = { kill(pid, SIGKILL) }
        let outBox = DataBox(), errBox = DataBox(), statusBox = DataBox()
        let group = DispatchGroup()
        for (fd, cap, box) in [(child.stdout, maxStdout, outBox), (child.stderr, maxStderr, errBox),
                               (child.status, maxStatus, statusBox)] {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                let (data, exceeded) = CappedRead.read(fd: fd, limit: cap)
                if exceeded { overflow.set(); killChild() }
                box.set(data)
                group.leave()
            }
        }
        let input = stdin ?? Data()
        let stdinFD = child.stdin
        DispatchQueue.global(qos: .userInitiated).async {
            CappedRead.writeAll(input, to: stdinFD)
            close(stdinFD)
        }

        // Waits without reaping, so a kill below can never hit a recycled pid.
        let exited = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            var info = siginfo_t()
            while waitid(P_PID, id_t(pid), &info, WEXITED | WNOWAIT) != 0 && errno == EINTR {}
            exited.signal()
        }
        var timedOut = false
        if exited.wait(timeout: .now() + limit) == .timedOut {
            timedOut = true
            kill(pid, SIGTERM)
            if exited.wait(timeout: .now() + 3) == .timedOut {
                kill(pid, SIGKILL)
                _ = exited.wait(timeout: .now() + 3)
            }
        }
        cancellation?.unregister(pid)
        var rawStatus: Int32 = 0
        while waitpid(pid, &rawStatus, timedOut ? WNOHANG : 0) < 0 && errno == EINTR {}
        _ = group.wait(timeout: .now() + 5)

        if !registered || cancellation?.isCancelled == true { throw GPGError.cancelled }
        if overflow.isSet { throw GPGError.outputTooLarge }
        if timedOut { throw limitedByDeadline ? GPGError.deadlineExceeded : GPGError.timedOut }

        let exitCode = (rawStatus & 0x7f) == 0 ? (rawStatus >> 8) & 0xff : 128 + (rawStatus & 0x7f)
        return GPGProcessResult(
            exitCode: exitCode,
            stdout: outBox.get(),
            stderr: errBox.get(),
            status: GPGStatusParser.parse(statusBox.get())
        )
    }

    // MARK: - Operations

    public func version() throws -> String {
        let r = try run(["--version"])
        let first = Bytes.string([UInt8](r.stdout)).split(separator: "\n").first.map(String.init) ?? ""
        guard r.exitCode == 0, !first.isEmpty else { throw GPGError.operationFailed(r.diagnostics) }
        try GPGVersion.requireSupported(first)
        return first
    }

    public func listKeys(secret: Bool, patterns: [String] = []) throws -> [KeyInfo] {
        let r = try run(["--fixed-list-mode", "--with-fingerprint", "--with-subkey-fingerprint",
                         secret ? "--list-secret-keys" : "--list-keys", "--"] + patterns)
        let parsed = GPGColonsParser.parseKeys(Bytes.string([UInt8](r.stdout)))
        if parsed.isEmpty && r.exitCode != 0 && patterns.isEmpty {
            throw GPGError.operationFailed(r.diagnostics)
        }
        return KeyInfo.withEmailUserIDsOnly(parsed)
    }

    public func sign(_ data: Data, signerFingerprint: String) throws -> (signature: Data, micalg: String) {
        let r = try run(["--armor", "--detach-sign", "--local-user", signerFingerprint, "--output", "-"], stdin: data)
        guard let created = r.status.lazy.compactMap({ line -> Int? in
            if case let .sigCreated(_, _, hash, _, _, _) = line.status { return hash }
            return nil
        }).first, r.exitCode == 0, !r.stdout.isEmpty else {
            throw failure(r, fallback: .operationFailed(r.diagnostics))
        }
        guard let micalg = Micalg.name(forHashAlgorithm: created) else {
            throw GPGError.operationFailed("unsupported hash algorithm \(created)")
        }
        return (r.stdout, micalg)
    }

    public func encrypt(_ data: Data, recipients: [String], hiddenRecipients: [String], signerFingerprint: String?) throws -> Data {
        guard !(recipients.isEmpty && hiddenRecipients.isEmpty) else { throw GPGError.noRecipients }
        var args = ["--armor", "--encrypt", "--output", "-"]
        // Recipients given as full fingerprints were resolved and vetted by the caller (GPGService: usable,
        // encryption-capable, matching user ID not revoked/expired). For this one call only, gpg is told not to
        // consult key validity, so keys of unknown validity can be used; gpg still refuses revoked, expired or
        // encryption-incapable keys. User ID specs keep gpg's normal trust checks.
        if (recipients + hiddenRecipients).allSatisfy(GPGRunner.isFingerprint) {
            args = ["--trust-model", "always"] + args
        }
        for r in recipients { args += ["--recipient", r] }
        for r in hiddenRecipients { args += ["--hidden-recipient", r] }
        if let signerFingerprint { args += ["--sign", "--local-user", signerFingerprint] }
        let r = try run(args, stdin: data)
        let invalid = invalidRecipients(r)
        if !invalid.isEmpty { throw GPGError.invalidRecipients(invalid) }
        guard r.exitCode == 0, r.has("END_ENCRYPTION"), !r.stdout.isEmpty else {
            throw failure(r, fallback: .operationFailed(r.diagnostics))
        }
        if signerFingerprint != nil, !r.has("SIG_CREATED") {
            throw failure(r, fallback: .operationFailed("signature was not created"))
        }
        return r.stdout
    }

    /// True for a full v4 (40 hex) or v5/v6 (64 hex) fingerprint.
    static func isFingerprint(_ spec: String) -> Bool {
        (spec.count == 40 || spec.count == 64) && spec.allSatisfy(\.isHexDigit)
    }

    public func decrypt(_ data: Data, interactive: Bool) throws -> DecryptResult {
        // "error" rather than "cancel": gpg-agent then reports GPG_ERR_NO_PIN_ENTRY (85) instead of
        // GPG_ERR_CANCELED (99), so a skipped prompt is distinguishable from a user cancelling a real one.
        let pinentry = interactive ? [] : ["--pinentry-mode", "error"]
        let r = try run(pinentry + ["--decrypt", "--output", "-"], stdin: data)
        return try GPGRunner.evaluateDecryption(r)
    }

    /// Applies the decryption security rules. Plaintext is only returned if decryption verifiably succeeded
    /// with integrity protection.
    static func evaluateDecryption(_ r: GPGProcessResult) throws -> DecryptResult {
        var encTo: [String] = []
        var noSeckey: [String] = []
        var began = false, okay = false, failed = false, noMDC = false
        for l in r.status {
            switch l.status {
            case let .encTo(k, _, _): encTo.append(k)
            case let .noSeckey(k): noSeckey.append(k)
            case .beginDecryption: began = true
            case .decryptionOkay: okay = true
            case .decryptionFailed: failed = true
            case let .decryptionInfo(mdc, _, aead): if mdc == 0 && aead == 0 { noMDC = true }
            case let .error(loc, _): if loc.hasPrefix("decrypt") || loc.contains("mdc") { failed = true }
            default: break
            }
        }
        let stderrText = Bytes.string([UInt8](r.stderr))
        if stderrText.contains("not integrity protected") || stderrText.contains("integrity check failed")
            || stderrText.contains("MDC check failed") || stderrText.contains("has been manipulated") {
            noMDC = true
        }
        let encrypted = began || !encTo.isEmpty
        let signatures = GPGStatusParser.signatures(from: r.status)

        if encrypted {
            if noMDC { throw GPGError.integrityCheckFailed }
            if failed || !okay {
                let mapped = failure(r, fallback: .decryptionFailed(r.diagnostics))
                if mapped == .needsPassphrase { throw mapped }
                if !noSeckey.isEmpty && noSeckey.count >= encTo.count { throw GPGError.noSecretKey(noSeckey) }
                throw mapped
            }
            return DecryptResult(plaintext: r.stdout, wasEncrypted: true, signatures: signatures,
                                 encryptedTo: encTo, integrityProtected: true)
        }
        // Not encrypted: only acceptable as signed data with an actual literal data packet.
        if failed || r.has("NODATA") || !r.has("PLAINTEXT") || signatures.isEmpty && r.exitCode != 0 {
            throw failure(r, fallback: .decryptionFailed(r.diagnostics.isEmpty ? "no OpenPGP data" : r.diagnostics))
        }
        return DecryptResult(plaintext: r.stdout, wasEncrypted: false, signatures: signatures,
                             encryptedTo: [], integrityProtected: false)
    }

    public func verify(_ data: Data, detachedSignature: Data) throws -> [SignatureResult] {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("sigil-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: dir) }
        let sigURL = dir.appendingPathComponent("signature.asc")
        guard fm.createFile(atPath: sigURL.path, contents: detachedSignature, attributes: [.posixPermissions: 0o600]) else {
            throw GPGError.operationFailed("could not write temporary signature file")
        }
        let r = try run(["--verify", "--", sigURL.path, "-"], stdin: data)
        let sigs = GPGStatusParser.signatures(from: r.status)
        if sigs.isEmpty { throw failure(r, fallback: .noSignatureFound) }
        return sigs
    }

    public func verifyInline(_ data: Data) throws -> (plaintext: Data, signatures: [SignatureResult]) {
        // Verifying never needs a secret key, so never ask for a passphrase.
        let r = try run(["--pinentry-mode", "error", "--decrypt", "--output", "-"], stdin: data)
        let result = try GPGRunner.evaluateDecryption(r)
        if result.signatures.isEmpty { throw GPGError.noSignatureFound }
        return (result.plaintext, result.signatures)
    }

    // MARK: - gpgconf

    /// gpgconf next to the gpg binary.
    public var gpgconfPath: URL { gpgPath.deletingLastPathComponent().appendingPathComponent("gpgconf") }

    func runGPGConf(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = gpgconfPath
        process.arguments = (homeDir.map { ["--homedir", $0.path] } ?? []) + arguments
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            throw GPGError.launchFailed(error.localizedDescription)
        }
        let output = (try? outPipe.fileHandleForReading.readToEnd()) ?? Data()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw GPGError.operationFailed("gpgconf \(arguments.joined(separator: " ")) exited with \(process.terminationStatus)")
        }
        return Bytes.string([UInt8](output))
    }

    /// The GnuPG home directory (from `gpgconf --list-dirs homedir`).
    public func homeDirectory() throws -> URL {
        let homedir = try runGPGConf(["--list-dirs", "homedir"]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !homedir.isEmpty else { throw GPGError.operationFailed("gpgconf reported no homedir") }
        // gpgconf percent-escapes special characters (e.g. %3a for ':').
        let path = homedir.removingPercentEncoding ?? homedir
        return URL(fileURLWithPath: path, isDirectory: true)
    }

    public func agentConfigURL() throws -> URL {
        try homeDirectory().appendingPathComponent("gpg-agent.conf")
    }

    public func reloadAgent() throws {
        _ = try runGPGConf(["--reload", "gpg-agent"])
    }

    public func dirmngrConfigURL() throws -> URL {
        try homeDirectory().appendingPathComponent("dirmngr.conf")
    }

    public func configuredKeyserver() throws -> String? {
        DirmngrConfig.keyserver(fromGPGConfOptions: try runGPGConf(["--list-options", "dirmngr"]))
    }

    public func reloadDirmngr() throws {
        _ = try runGPGConf(["--reload", "dirmngr"])
    }

    // MARK: - Error mapping

    func invalidRecipients(_ r: GPGProcessResult) -> [InvalidKeySpec] {
        r.status.compactMap {
            if case let .invRecp(reason, spec) = $0.status { return InvalidKeySpec(reason: reason, spec: spec) }
            return nil
        }
    }

    static let passphraseErrorCodes: Set<Int> = [11, 85, 99, 177]

    static func failure(_ r: GPGProcessResult, fallback: GPGError) -> GPGError {
        var invSigners: [InvalidKeySpec] = []
        for l in r.status {
            switch l.status {
            case .badPassphrase, .missingPassphrase:
                return .needsPassphrase
            case let .error(_, code), let .failure(_, code):
                if passphraseErrorCodes.contains(code) { return .needsPassphrase }
            case let .invSgnr(reason, spec):
                invSigners.append(InvalidKeySpec(reason: reason, spec: spec))
            default: break
            }
        }
        if !invSigners.isEmpty { return .invalidSigner(invSigners) }
        return fallback
    }

    func failure(_ r: GPGProcessResult, fallback: GPGError) -> GPGError {
        GPGRunner.failure(r, fallback: fallback)
    }
}

/// Thread-safe holder for data produced on a background queue.
final class DataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func set(_ d: Data) { lock.lock(); data = d; lock.unlock() }
    func get() -> Data { lock.lock(); defer { lock.unlock() }; return data }
}
