import Foundation
import XCTest
@testable import SigilCore

// Tests for the fixes of the security audit (one section per finding).

/// Forwards to a real runner and counts the gpg calls that touch message data.
final class CountingGPG: GPGRunning, @unchecked Sendable {
    let base: GPGRunner
    private let lock = NSLock()
    private var calls = 0
    init(_ base: GPGRunner) { self.base = base }
    var dataCalls: Int { lock.lock(); defer { lock.unlock() }; return calls }
    private func count() { lock.lock(); calls += 1; lock.unlock() }

    func version() throws -> String { try base.version() }
    func listKeys(secret: Bool, patterns: [String]) throws -> [KeyInfo] { try base.listKeys(secret: secret, patterns: patterns) }
    func sign(_ data: Data, signerFingerprint: String) throws -> (signature: Data, micalg: String) {
        try base.sign(data, signerFingerprint: signerFingerprint)
    }
    func encrypt(_ data: Data, recipients: [String], hiddenRecipients: [String], signerFingerprint: String?) throws -> Data {
        try base.encrypt(data, recipients: recipients, hiddenRecipients: hiddenRecipients, signerFingerprint: signerFingerprint)
    }
    func decrypt(_ data: Data, interactive: Bool) throws -> DecryptResult { count(); return try base.decrypt(data, interactive: interactive) }
    func verify(_ data: Data, detachedSignature: Data) throws -> [SignatureResult] {
        count(); return try base.verify(data, detachedSignature: detachedSignature)
    }
    func verifyInline(_ data: Data) throws -> (plaintext: Data, signatures: [SignatureResult]) { count(); return try base.verifyInline(data) }
    func agentConfigURL() throws -> URL { try base.agentConfigURL() }
    func reloadAgent() throws { try base.reloadAgent() }
    func dirmngrConfigURL() throws -> URL { try base.dirmngrConfigURL() }
    func configuredKeyserver() throws -> String? { try base.configuredKeyserver() }
    func reloadDirmngr() throws { try base.reloadDirmngr() }
}

/// A directory outside /tmp for files the gpg path validator must look at (it forbids temporary directories).
func makeScratchDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("sigil-audit-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func writeScript(_ body: String, named name: String, in directory: URL, mode: Int = 0o755) throws -> URL {
    let url = directory.appendingPathComponent(name)
    try Data(("#!/bin/sh\n" + body + "\n").utf8).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    return url
}

final class SecurityAuditTests: XCTestCase {
    nonisolated(unsafe) static var keyring: TestKeyring?
    nonisolated(unsafe) static var setupError: String?

    override class func setUp() {
        super.setUp()
        do { keyring = try TestKeyring() } catch { setupError = "\(error)" }
    }

    override class func tearDown() {
        keyring?.cleanup()
        keyring = nil
        super.tearDown()
    }

    func ring() throws -> TestKeyring {
        guard let k = SecurityAuditTests.keyring else { throw XCTSkip("no test keyring: \(SecurityAuditTests.setupError ?? "")") }
        return k
    }

    // MARK: HIGH: no silent key substitution

    func key(_ fingerprint: String, validity: String = "-", created: TimeInterval = 0,
             email: String = "carol@example.org") -> KeyInfo {
        KeyInfo(fingerprint: fingerprint, keyID: String(fingerprint.suffix(16)), isSecret: false, validity: validity,
                ownerTrust: "-", algorithm: 22, length: 255, curve: nil, created: Date(timeIntervalSince1970: created),
                expires: nil, capabilities: KeyCapabilities(sign: true, encrypt: true), isDisabled: false,
                userIDs: [UserID(uid: "Carol <\(email)>", validity: validity)], subkeys: [])
    }

    func testResolutionRefusesToGuessBetweenUnverifiedKeys() {
        let a = String(repeating: "A", count: 40), b = String(repeating: "B", count: 40)
        let email = "carol@example.org"
        func resolve(_ keys: [KeyInfo], preferred: String? = nil) -> RecipientKeyResolution {
            RecipientKeyChoice.resolve(from: keys, email: email, preferred: preferred)
        }
        XCTAssertEqual(resolve([]), .missing)
        XCTAssertEqual(resolve([key(a)]).key?.fingerprint, a, "a single unverified key is used (and annotated)")
        let twoUnverified = [key(a, created: 1), key(b, created: 2)]
        guard case let .ambiguous(keys) = resolve(twoUnverified) else { return XCTFail("expected ambiguous") }
        XCTAssertEqual(Set(keys.map(\.fingerprint)), [a, b], "never the newest silently")
        XCTAssertEqual(resolve(twoUnverified, preferred: a).key?.fingerprint, a, "a preference resolves it")
        XCTAssertEqual(resolve([key(a, validity: "f", created: 1), key(b, created: 2)]).key?.fingerprint, a,
                       "a verified key resolves it")
        XCTAssertEqual(resolve([key(a, validity: "u"), key(b, validity: "f", created: 5)]).key?.fingerprint, b,
                       "among verified keys the newest")
        // An expired second key does not make it ambiguous.
        XCTAssertEqual(resolve([key(a), key(b, validity: "e")]).key?.fingerprint, a)
    }

    /// Imports keys made in a separate home, so they have unknown validity in the test home.
    func makeUnverifiedHome(uids: [String]) throws -> (GPGRunner, [String], () -> Void) {
        let home = try TestKeyring.makeHome(), source = try TestKeyring.makeHome()
        var fingerprints: [String] = []
        for uid in uids { fingerprints.append(try TestKeyring.generate(uid, in: source)) }
        // A signing key of our own in the target home.
        _ = try TestKeyring.generate("Alice <alice@example.org>", in: home)
        let export = try runCLI(TestKeyring.gpgPath, ["--homedir", source.path, "--batch", "--export"] + fingerprints)
        let imported = try runCLI(TestKeyring.gpgPath, ["--homedir", home.path, "--batch", "--import"], stdin: export.stdout)
        XCTAssertEqual(imported.exitCode, 0, imported.stderr)
        let cleanup = {
            for h in [home, source] {
                _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", h.path, "--kill", "all"])
                try? FileManager.default.removeItem(at: h)
            }
        }
        return (GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: home, timeout: 30), fingerprints, cleanup)
    }

    func testServiceReportsAndRefusesAmbiguousRecipients() throws {
        let (runner, fingerprints, cleanup) = try makeUnverifiedHome(uids: [
            "Carol <carol@example.org>", "Carol (new) <carol@example.org>", "Dave <dave@example.org>",
        ])
        defer { cleanup() }
        let preferences = PreferredKeyStore(fileURL: try TestKeyring.makeHome().appendingPathComponent("preferred.json"))
        let service = GPGService(runner: runner, preferredKeys: preferences)

        let status = try service.encodingStatus(from: "alice@example.org",
                                                recipients: ["Carol <carol@example.org>", "dave@example.org"])
        XCTAssertEqual(status.ambiguousRecipients, ["Carol <carol@example.org>"])
        XCTAssertEqual(status.unverifiedRecipients, ["dave@example.org"], "one unverified key: used, but marked")
        XCTAssertEqual(status.missingRecipients, [])

        for (to, bcc) in [(["carol@example.org"], [String]()), (["dave@example.org"], ["carol@example.org"])] {
            XCTAssertThrowsError(try service.encode(message: sampleMessage(), sign: false, encrypt: true,
                                                    from: "alice@example.org", recipients: to, hiddenRecipients: bcc)) {
                XCTAssertEqual($0 as? GPGError, .ambiguousRecipients(["carol@example.org"]))
                XCTAssertEqual(($0 as? LocalizedError)?.errorDescription,
                               "carol@example.org has several unverified keys. Choose one under Public Keys > Prefer "
                               + "for carol@example.org in the Sigil app.")
            }
        }
        XCTAssertNoThrow(try service.encode(message: sampleMessage(), sign: false, encrypt: true, from: "alice@example.org",
                                            recipients: ["dave@example.org"], hiddenRecipients: []))

        // Preferring one key resolves it.
        _ = try service.setPreferredKey(email: "carol@example.org", fingerprint: fingerprints[0])
        XCTAssertEqual(try service.encodingStatus(from: "alice@example.org", recipients: ["carol@example.org"]).ambiguousRecipients, [])
        XCTAssertNoThrow(try service.encode(message: sampleMessage(), sign: false, encrypt: true, from: "alice@example.org",
                                            recipients: ["carol@example.org"], hiddenRecipients: []))
    }

    // MARK: MED 1: signer is not the sender

    func testGoodSignatureFromAnotherAddressIsAProblem() throws {
        let signer = SignerInfo(fingerprint: String(repeating: "C", count: 40), keyID: "CCCCCCCCCCCCCCCC",
                                email: "eve@example.org", userID: "Eve <eve@example.org>", validity: .fully, status: .good,
                                matchesSender: false)
        let original = sampleMessage()
        let outcome = DecodeOutcome(message: original, classification: .pgpMimeSigned, encrypted: false, signed: true,
                                    partial: false, signers: [signer], error: nil, needsPassphrase: false)
        XCTAssertEqual(MessageMark.of(outcome), .yellow)
        let p = DecodePresentation.make(outcome: outcome, original: original)
        let expected = "Signed by a different address: Eve <eve@example.org> is not the sender alice@example.org."
        XCTAssertTrue(p.signers.isEmpty, "no Mail badge")
        XCTAssertEqual(p.banner?.title, expected)
        XCTAssertEqual(p.signingError, expected)
        XCTAssertTrue(p.rawData.string.contains(expected), "the warning box shows it too")
        XCTAssertTrue(p.rawData.string.contains("#f9a825"), "yellow box")

        var matching = signer
        matching.matchesSender = true
        let fine = DecodePresentation.make(outcome: DecodeOutcome(message: original, classification: .pgpMimeSigned,
                                                                  encrypted: false, signed: true, partial: false,
                                                                  signers: [matching], error: nil, needsPassphrase: false),
                                           original: original)
        XCTAssertEqual(fine.signers.count, 1)
        XCTAssertNil(fine.banner)
    }

    // MARK: MED 2: linear armor scan with caps

    func testUnterminatedBeginLinesAreClassifiedQuickly() {
        let text = String(repeating: "-----BEGIN PGP MESSAGE-----\r\n", count: 30_000)
        let message = sampleMessage(body: text, contentType: "text/plain", cte: "7bit")
        let started = Date()
        XCTAssertEqual(PGPDetector.classify(messageData: message), .none, "no complete block")
        XCTAssertFalse(PGPDetector.isComplete(messageData: message))
        let scan = Armor.scan(Data(text.utf8))
        XCTAssertTrue(scan.blocks.isEmpty)
        XCTAssertTrue(scan.unterminated)
        XCTAssertLessThan(Date().timeIntervalSince(started), 1.0)
    }

    func testArmorCaps() {
        let block = "-----BEGIN PGP MESSAGE-----\r\n\r\nhQEMA\r\n-----END PGP MESSAGE-----\r\n"
        let many = String(repeating: block, count: Armor.maxBlocks + 1)
        let scan = Armor.scan(Data(many.utf8))
        XCTAssertTrue(scan.truncated)
        XCTAssertEqual(scan.blocks.count, Armor.maxBlocks)
        let message = sampleMessage(body: many, contentType: "text/plain", cte: "7bit")
        XCTAssertEqual(PGPDetector.classify(messageData: message), .inline, "still PGP")
        XCTAssertFalse(PGPDetector.isComplete(messageData: message), "neutral preview, no gpg")

        let big = block + String(repeating: "x", count: Armor.maxScanBytes)
        XCTAssertTrue(Armor.scan(Data(big.utf8)).truncated)
        XCTAssertFalse(PGPDetector.isComplete(messageData: sampleMessage(body: big, contentType: "text/plain", cte: "7bit")))
        // An unterminated block before a complete one: the complete one is found, the message is incomplete.
        let mixed = Armor.scan(Data(("-----BEGIN PGP MESSAGE-----\r\nabc\r\n" + block).utf8))
        XCTAssertEqual(mixed.blocks.count, 1)
        XCTAssertTrue(mixed.unterminated)
    }

    // MARK: MED 3: output caps (compression bomb)

    func testCompressionBombIsStoppedAtTheOutputCap() throws {
        let k = try ring()
        let zeros = Data(count: 300 * 1024 * 1024)
        let signed = try k.gpg(["--armor", "--sign", "--local-user", k.alice, "--compress-level", "9"], stdin: zeros)
        XCTAssertEqual(signed.exitCode, 0, signed.stderr)
        XCTAssertLessThan(signed.stdout.count, 2 * 1024 * 1024, "a small message")

        let capped = GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: k.home, timeout: 30,
                               maxStdout: 1024 * 1024)
        let started = Date()
        XCTAssertThrowsError(try capped.decrypt(signed.stdout, interactive: false)) {
            XCTAssertEqual($0 as? GPGError, .outputTooLarge)
        }
        let message = sampleMessage(body: LineEndings.toCRLF(signed.stdout).string, contentType: "text/plain", cte: "7bit")
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: message, gpg: capped))
        XCTAssertNil(outcome.message, "no plaintext")
        XCTAssertEqual(outcome.error, GPGError.outputTooLarge.errorDescription)
        XCTAssertLessThan(Date().timeIntervalSince(started), 10)
    }

    // MARK: MED 4: no automatic decryption of mixed content

    func encryptedArmor(_ text: String) throws -> String {
        let k = try ring()
        let r = try k.gpg(["--armor", "--encrypt", "--recipient", k.bob], stdin: Data(text.utf8))
        XCTAssertEqual(r.exitCode, 0, r.stderr)
        return LineEndings.toCRLF(r.stdout).string
    }

    func testNestedEncryptedPartIsNotDecryptedAutomatically() throws {
        let k = try ring()
        let encrypted = try PGPMIMEEncoder.encrypt(message: sampleMessage(), recipients: [k.bob], hidden: [],
                                                   signer: nil, gpg: k.runner)
        let msg = RFC822Message(data: encrypted)
        let attacker = Data("Content-Type: text/html\r\n\r\n<img src=\"http://evil.example/?\">\r\n".utf8)
        let mixedBody = MIMEBuilder.entity(headers: [("Content-Type", "multipart/mixed; boundary=\"efail\"")],
                                           body: MIMEBuilder.multipartBody(parts: [attacker, msg.bodyEntity], boundary: "efail"))
        let mixed = RFC822Message.combine(outerHeaders: msg.outerHeaders, bodyEntity: mixedBody)

        let counting = CountingGPG(k.runner)
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: mixed, gpg: counting))
        XCTAssertTrue(outcome.mixedEncryption)
        XCTAssertEqual(outcome.message, mixed, "the original, nothing decrypted")
        XCTAssertFalse(outcome.encrypted)
        XCTAssertEqual(counting.dataCalls, 0, "gpg never ran")

        let p = DecodePresentation.make(outcome: outcome, original: mixed)
        XCTAssertEqual(p.banner?.title, DecodePresentation.mixedEncryptionTitle)
        XCTAssertEqual(p.banner?.actionTitle, "Decrypt anyway")
        XCTAssertEqual(MessageContext.decode(try XCTUnwrap(p.context))?.action, .decryptMixed)
        XCTAssertTrue(p.blocksRemoteContent)
        XCTAssertEqual(p.rawData, mixed)
        XCTAssertFalse(p.isEncrypted)

        // On explicit request it decrypts; the text is for Sigil's own view only.
        let anyway = try XCTUnwrap(PGPMIMEDecoder.decode(message: mixed, gpg: k.runner, allowMixed: true))
        XCTAssertTrue(anyway.encrypted)
        XCTAssertTrue(anyway.partial)
        let text = MixedDecryption.readableText(of: try XCTUnwrap(anyway.message))
        XCTAssertTrue(text.contains("Umlauts: äöü"), text)
        XCTAssertTrue(text.contains("[text/html part not shown]"), text)
        XCTAssertFalse(text.contains("evil.example"))
    }

    func testInlineArmorWithOtherContentIsMixed() throws {
        let k = try ring()
        let armor = try encryptedArmor("Secret\n")
        let cases = [
            "Please read:\r\n" + armor,                         // text around the block
            armor + "\r\n" + (try encryptedArmor("Second\n")),  // two encrypted blocks
        ]
        for body in cases {
            let message = sampleMessage(body: body, contentType: "text/plain", cte: "7bit")
            let counting = CountingGPG(k.runner)
            let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: message, gpg: counting))
            XCTAssertTrue(outcome.mixedEncryption)
            XCTAssertEqual(counting.dataCalls, 0)
        }
        // A whole-message block (whitespace around it only) still decrypts automatically.
        let whole = sampleMessage(body: "\r\n  \r\n" + armor + "\r\n\r\n", contentType: "text/plain", cte: "7bit")
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: whole, gpg: k.runner))
        XCTAssertFalse(outcome.mixedEncryption)
        XCTAssertTrue(outcome.encrypted)
        XCTAssertNotNil(outcome.message)
        // Signed-only armor next to other text is verified as before (partial), not treated as encrypted.
        let clear = try k.gpg(["--local-user", k.alice, "--clearsign"], stdin: Data("Signed text\n".utf8))
        let signedMixed = sampleMessage(body: "Intro\r\n" + LineEndings.toCRLF(clear.stdout).string, contentType: "text/plain",
                                        cte: "7bit")
        let signed = try XCTUnwrap(PGPMIMEDecoder.decode(message: signedMixed, gpg: k.runner))
        XCTAssertFalse(signed.mixedEncryption)
        XCTAssertEqual(signed.signers.map(\.status), [.good])
    }

    func testFirstPacketSniffing() throws {
        let k = try ring()
        let encrypted = Armor.blocks(in: try encryptedArmor("x\n"))
        XCTAssertTrue(Armor.mayBeEncrypted(try XCTUnwrap(encrypted.first)))
        let signed = try k.gpg(["--armor", "--sign", "--local-user", k.alice], stdin: Data("x\n".utf8))
        XCTAssertFalse(Armor.mayBeEncrypted(try XCTUnwrap(Armor.blocks(in: signed.stdout).first)))
        let garbage = Armor.blocks(in: "-----BEGIN PGP MESSAGE-----\n\n!!!!\n-----END PGP MESSAGE-----\n")
        XCTAssertTrue(Armor.mayBeEncrypted(try XCTUnwrap(garbage.first)), "unreadable counts as encrypted")
    }

    // MARK: LOW 1: per-message limits

    func testTooManyPGPPartsRunNoGPG() throws {
        let k = try ring()
        let clear = LineEndings.toCRLF(try k.gpg(["--local-user", k.alice, "--clearsign"], stdin: Data("x\n".utf8)).stdout).string
        var parts: [Data] = []
        for _ in 0...PGPMIMEDecoder.maxPGPParts {
            parts.append(Data(("Content-Type: text/plain\r\n\r\n" + clear).utf8))
        }
        let body = MIMEBuilder.entity(headers: [("Content-Type", "multipart/mixed; boundary=\"many\"")],
                                      body: MIMEBuilder.multipartBody(parts: parts, boundary: "many"))
        let message = RFC822Message.combine(outerHeaders: RFC822Message(data: sampleMessage()).outerHeaders, bodyEntity: body)
        let counting = CountingGPG(k.runner)
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: message, gpg: counting))
        XCTAssertNil(outcome.message)
        XCTAssertTrue(outcome.error?.contains("at most 16") ?? false, outcome.error ?? "")
        XCTAssertEqual(counting.dataCalls, 0)
    }

    func testDeadlineAndCancellationStopGPG() throws {
        let directory = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let sleeper = try writeScript("exec sleep 20", named: "gpg", in: directory)

        let past = GPGRunner(gpgPath: sleeper, deadline: Date() - 1)
        XCTAssertThrowsError(try past.run(["--version"])) { XCTAssertEqual($0 as? GPGError, .deadlineExceeded) }

        var started = Date()
        let soon = GPGRunner(gpgPath: sleeper, timeout: 60, deadline: Date() + 0.5)
        XCTAssertThrowsError(try soon.run([])) { XCTAssertEqual($0 as? GPGError, .deadlineExceeded) }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)

        let cancellation = GPGCancellation()
        let cancellable = GPGRunner(gpgPath: sleeper, timeout: 60, cancellation: cancellation)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { cancellation.cancel() }
        started = Date()
        XCTAssertThrowsError(try cancellable.run([])) { XCTAssertEqual($0 as? GPGError, .cancelled) }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
        XCTAssertThrowsError(try cancellable.run([])) { XCTAssertEqual($0 as? GPGError, .cancelled, "stays cancelled") }

        // The service applies its cancellation to every runner it hands out.
        let service = GPGService(runner: GPGRunner(gpgPath: sleeper, timeout: 60))
        service.cancelAll()
        var reply = ""
        service.ping { reply = $0 }
        XCTAssertEqual(reply, "error: " + (GPGError.cancelled.errorDescription ?? ""))
    }

    // MARK: LOW 2: per-caller permissions

    func testAuthorizationTable() {
        let extensionAllowed: Set<ServiceMethod> = [.ping, .listKeys, .encodingStatus, .encode, .decode]
        for method in ServiceMethod.allCases {
            XCTAssertTrue(ServiceAuthorization.isAllowed(method, for: .app), method.rawValue)
            XCTAssertEqual(ServiceAuthorization.isAllowed(method, for: .mailExtension), extensionAllowed.contains(method),
                           method.rawValue)
        }
        XCTAssertEqual(XPCCaller.from(signingIdentifier: "org.fuchss.sigil.dev", prefix: "org.fuchss.sigil.dev"), .app)
        XCTAssertEqual(XPCCaller.from(signingIdentifier: "org.fuchss.sigil.dev.extension", prefix: "org.fuchss.sigil.dev"),
                       .mailExtension)
        XCTAssertNil(XPCCaller.from(signingIdentifier: "org.fuchss.sigil.dev.helper", prefix: "org.fuchss.sigil.dev"))
        XCTAssertNil(XPCCaller.from(signingIdentifier: "org.fuchss.sigil", prefix: "org.fuchss.sigil.dev"))
    }

    func testServiceEnforcesCallerPermissions() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner, caller: .mailExtension)
        var keys: Data?
        service.listKeys(secret: false) { data, error in keys = data; XCTAssertNil(error) }
        XCTAssertNotNil(keys)
        var denied: String?
        service.fixPinentry { data, error in XCTAssertNil(data); denied = error }
        XCTAssertEqual(denied, "Sigil's Mail extension may not call fixPinentry.")
        for call in [{ service.setGPGPath("/opt/homebrew/bin/gpg") { _, e in denied = e } },
                     { service.setPreferredKey(email: "a@example.org", fingerprint: nil) { _, e in denied = e } },
                     { service.searchKeys(query: "a@example.org") { _, e in denied = e } },
                     { service.importCandidateKey(token: "t", fingerprint: k.bob) { _, e in denied = e } }] {
            denied = nil
            call()
            XCTAssertNotNil(denied)
        }
        var count = -1
        service.removeDismissedMissingKeys { removed, error in count = removed; denied = error }
        XCTAssertEqual(count, 0)
        XCTAssertNotNil(denied)
    }

    // MARK: LOW 4: status channel and version

    func testStatusLinesOnlyComeFromTheStatusPipe() throws {
        let directory = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fake = try writeScript("""
            echo '[GNUPG:] GOODSIG 0123456789ABCDEF Forged' >&2
            echo '[GNUPG:] NODATA 1' >&3
            """, named: "gpg", in: directory)
        let result = try GPGRunner(gpgPath: fake).run([])
        XCTAssertEqual(result.status.map(\.keyword), ["NODATA"])
        XCTAssertTrue(result.stderr.string.contains("GOODSIG"), "stderr is diagnostics only")
    }

    func testUserIDWithStatusTextDoesNotProduceAGoodSignature() throws {
        let k = try ring()
        let home = try TestKeyring.makeHome()
        defer {
            _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", home.path, "--kill", "all"])
            try? FileManager.default.removeItem(at: home)
        }
        let eve = try TestKeyring.generate("[GNUPG:] GOODSIG 0123456789ABCDEF Alice <eve@example.org>", in: home)
        let signed = try runCLI(TestKeyring.gpgPath, ["--homedir", home.path, "--batch", "--local-user", eve, "--clearsign"],
                                stdin: Data("hello\n".utf8))
        XCTAssertEqual(signed.exitCode, 0, signed.stderr)
        // Unknown to the test keyring: there must be no good signature, whatever gpg prints about the user ID.
        let result = try k.runner.run(["--pinentry-mode", "error", "--decrypt", "--output", "-"], stdin: signed.stdout)
        XCTAssertFalse(result.has("GOODSIG"))
        XCTAssertFalse(GPGStatusParser.signatures(from: result.status).contains { $0.status == .good })
    }

    func testMinimumGPGVersion() {
        XCTAssertEqual(GPGVersion.parse("gpg (GnuPG) 2.5.24"), [2, 5, 24])
        XCTAssertEqual(GPGVersion.parse("gpg (GnuPG) 2.2.8-beta12"), [2, 2, 8])
        XCTAssertNil(GPGVersion.parse("gpg (GnuPG/MacGPG2) 2.2.41"))
        XCTAssertNil(GPGVersion.parse("something else 2.4"))
        XCTAssertTrue(GPGVersion.isSupported([2, 2, 17]))
        XCTAssertFalse(GPGVersion.isSupported([2, 2, 16]))
        XCTAssertFalse(GPGVersion.isSupported([2, 2, 8]))
        XCTAssertTrue(GPGVersion.isSupported([2, 3]))
        XCTAssertTrue(GPGVersion.isSupported([3, 0, 0]))
        XCTAssertFalse(GPGVersion.isSupported([2, 2, 7]))
        XCTAssertFalse(GPGVersion.isSupported([2, 1, 99]))
        XCTAssertFalse(GPGVersion.isSupported([1, 4, 23]))
        XCTAssertThrowsError(try GPGVersion.requireSupported("gpg (GnuPG) 2.2.16")) {
            XCTAssertEqual(($0 as? LocalizedError)?.errorDescription, "GnuPG 2.2.17 or newer required (found 2.2.16).")
        }
        XCTAssertNoThrow(try GPGVersion.requireSupported("gpg (GnuPG) 2.4.5"))
    }

    // MARK: MED 5: gpg path validation and storage

    func testGPGPathValidation() throws {
        let real = try XCTUnwrap(GPGRunner.locateGPG())
        XCTAssertEqual(try GPGPathValidator.validate(real.path), real)

        func rejected(_ path: String, forbidden: [String]? = nil) -> Bool {
            (try? GPGPathValidator.validate(path, forbiddenPrefixes: forbidden)) == nil
        }
        XCTAssertTrue(rejected("gpg"), "relative")
        XCTAssertTrue(rejected("/opt/homebrew/bin/../bin/gpg"), "dot-dot")
        XCTAssertTrue(rejected("/nonexistent/gpg"))

        // A copy of a fake gpg next to a fake gpgconf, in /tmp: rejected for the location alone.
        let tmp = try TestKeyring.makeHome()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let tmpGPG = try writeScript("echo 'gpg (GnuPG) 2.4.0'", named: "gpg", in: tmp)
        _ = try writeScript("echo 'gpgconf (GnuPG) 2.4.0'", named: "gpgconf", in: tmp)
        XCTAssertTrue(rejected(tmpGPG.path))

        // Outside forbidden directories (none for this check): only a real, safe, new enough gpg passes.
        let directory = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fakeGPG = try writeScript("echo 'gpg (GnuPG) 2.4.0'", named: "gpg", in: directory)
        let fakeConf = try writeScript("echo 'gpgconf (GnuPG) 2.4.0'", named: "gpgconf", in: directory)
        XCTAssertNoThrow(try GPGPathValidator.validate(fakeGPG.path, forbiddenPrefixes: []))
        XCTAssertTrue(rejected(fakeGPG.path), "the default list forbids the temporary directory")

        _ = try writeScript("echo 'gpg (GnuPG) 2.2.7'", named: "gpg", in: directory)
        XCTAssertThrowsError(try GPGPathValidator.validate(fakeGPG.path, forbiddenPrefixes: [])) {
            XCTAssertEqual($0 as? GPGError, .unsupportedVersion("2.2.7"))
        }
        _ = try writeScript("echo 'Not GnuPG'", named: "gpg", in: directory)
        XCTAssertTrue(rejected(fakeGPG.path, forbidden: []), "not gpg")
        _ = try writeScript("echo 'gpg (GnuPG) 2.4.0'", named: "gpg", in: directory, mode: 0o775)
        XCTAssertTrue(rejected(fakeGPG.path, forbidden: []), "group-writable")
        _ = try writeScript("echo 'gpg (GnuPG) 2.4.0'", named: "gpg", in: directory, mode: 0o757)
        XCTAssertTrue(rejected(fakeGPG.path, forbidden: []), "world-writable")
        _ = try writeScript("echo 'gpg (GnuPG) 2.4.0'", named: "gpg", in: directory)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: fakeConf.path)
        XCTAssertTrue(rejected(fakeGPG.path, forbidden: []), "gpgconf next to it must pass the same checks")
        try FileManager.default.removeItem(at: fakeConf)
        XCTAssertTrue(rejected(fakeGPG.path, forbidden: []), "no gpgconf")
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("dir"), withIntermediateDirectories: true)
        XCTAssertTrue(rejected(directory.appendingPathComponent("dir").path, forbidden: []), "not a regular file")
    }

    func testGPGPathIsStoredByTheHelperOnly() throws {
        let k = try ring()
        let directory = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let settings = HelperSettings(fileURL: directory.appendingPathComponent("helper/settings.json"))
        let app = GPGService(runner: k.runner, caller: .app, settings: settings)
        let real = try XCTUnwrap(GPGRunner.locateGPG()).path

        XCTAssertThrowsError(try app.setGPGPath("/tmp/gpg"))
        XCTAssertNil(settings.gpgPath())
        XCTAssertEqual(try app.setGPGPath(real).configuredPath, real)
        XCTAssertEqual(HelperSettings(fileURL: settings.fileURL).gpgPath(), real, "persisted")
        XCTAssertNil(try app.setGPGPath("  ").configuredPath, "empty clears")

        let fromExtension = GPGService(runner: k.runner, caller: .mailExtension, settings: settings)
        var error: String?
        fromExtension.setGPGPath(real) { _, e in error = e }
        XCTAssertNotNil(error)
        XCTAssertNil(settings.gpgPath())

        // A symbolic link in place of the settings file is refused.
        try FileManager.default.removeItem(at: settings.fileURL)
        try FileManager.default.createSymbolicLink(at: settings.fileURL, withDestinationURL: directory.appendingPathComponent("x"))
        XCTAssertThrowsError(try settings.setGPGPath(real))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("x").path))
    }

    // MARK: LOW 5: every warning box comes with a banner

    func testEveryWarningBoxHasABanner() {
        let original = sampleMessage()
        func signer(_ status: SignatureStatus, validity: TrustLevel? = .fully, matches: Bool? = true) -> SignerInfo {
            SignerInfo(fingerprint: String(repeating: "D", count: 40), keyID: "DDDDDDDDDDDDDDDD", email: "alice@example.org",
                       userID: "Alice <alice@example.org>", validity: validity, status: status, matchesSender: matches)
        }
        var outcomes: [DecodeOutcome] = []
        let statuses: [SignatureStatus] = [.good, .bad, .expiredSignature, .expiredKey, .revokedKey, .noPublicKey, .error]
        for status in statuses {
            for validity in [TrustLevel.fully, .never, .undefined] {
                for matches in [true, false] {
                    for partial in [false, true] {
                        for encrypted in [false, true] {
                            outcomes.append(DecodeOutcome(message: original, classification: .pgpMimeSigned,
                                                          encrypted: encrypted, signed: true, partial: partial,
                                                          signers: [signer(status, validity: validity, matches: matches)],
                                                          error: nil, needsPassphrase: false))
                        }
                    }
                }
            }
        }
        outcomes.append(DecodeOutcome(message: nil, classification: .inline, encrypted: false, signed: false, partial: false,
                                      signers: [], error: "broken", needsPassphrase: false))
        outcomes.append(DecodeOutcome(message: nil, classification: .pgpMimeEncrypted, encrypted: true, signed: false,
                                      partial: false, signers: [], error: GPGError.integrityCheckFailed.errorDescription,
                                      needsPassphrase: false))
        var boxes = 0
        for outcome in outcomes {
            let p = DecodePresentation.make(outcome: outcome, original: original)
            guard p.rawData.string.contains("Sigil: ") else { continue }
            boxes += 1
            XCTAssertNotNil(p.banner, "box without banner for \(outcome.signers.map(\.status))")
            XCTAssertTrue(p.signers.isEmpty, "box with a Mail signed badge for \(outcome.signers.map(\.status))")
        }
        XCTAssertGreaterThan(boxes, 50)
    }

    // MARK: LOW 8: symlinks are refused

    func testStoresRefuseSymbolicLinks() throws {
        let directory = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target.json")
        try Data("[]".utf8).write(to: target)

        let missingURL = directory.appendingPathComponent("missing-keys.json")
        try FileManager.default.createSymbolicLink(at: missingURL, withDestinationURL: target)
        let missing = MissingKeyStore(fileURL: missingURL)
        XCTAssertThrowsError(try missing.record(keyID: "0123456789ABCDEF", fingerprint: nil, senderEmail: nil, signerUserID: nil))
        XCTAssertEqual(try Data(contentsOf: target), Data("[]".utf8), "target untouched")

        let lockedURL = directory.appendingPathComponent("locked.json")
        try FileManager.default.createSymbolicLink(at: URL(fileURLWithPath: lockedURL.path + ".lock"),
                                                   withDestinationURL: directory.appendingPathComponent("elsewhere"))
        XCTAssertThrowsError(try MissingKeyStore(fileURL: lockedURL)
            .record(keyID: "0123456789ABCDEF", fingerprint: nil, senderEmail: nil, signerUserID: nil))
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("elsewhere").path))

        let preferredURL = directory.appendingPathComponent("preferred-keys.json")
        try Data(#"{"carol@example.org":"AAAA"}"#.utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: preferredURL, withDestinationURL: target)
        let preferred = PreferredKeyStore(fileURL: preferredURL)
        XCTAssertEqual(preferred.all(), [:], "a linked file is not read")
        XCTAssertThrowsError(try preferred.set(email: "carol@example.org", fingerprint: "BBBB"))
    }

    // MARK: INFO 1: temporary home configuration

    func testTemporaryHomeConfigAllowlist() {
        let gpgConf = """
            # comment
            keyserver hkps://keys.example.org
            auto-key-locate local,wkd
            keyserver-options honor-keyserver-url,timeout=10 auto-key-retrieve include-revoked
            keyserver-options honor-keyserver-url
            trust-model tofu+pgp
            keyring /tmp/evil.kbx
            primary-keyring /tmp/evil.kbx
            homedir /tmp/elsewhere
            load-extension evil
            --keyserver hkps://dashed.example.org
            default-key ABCDEF
            """
        let filtered = TempHomeConfig.filteredGPGConf(gpgConf).split(separator: "\n").map(String.init).filter { !$0.hasPrefix("#") }
        XCTAssertEqual(filtered, ["keyserver hkps://keys.example.org", "auto-key-locate local,wkd",
                                  "keyserver-options timeout=10,include-revoked", "trust-model tofu+pgp",
                                  "keyserver hkps://dashed.example.org"])

        let dirmngr = """
            keyserver hkps://keys.openpgp.org
            hkp-cacert /etc/ca.pem
            honor-http-proxy
            http-proxy http://proxy:8080
            use-tor
            standard-resolver
            resolver-timeout 5
            log-file /tmp/log
            allow-version-check
            ldapserverlist-file /tmp/x
            """
        let kept = TempHomeConfig.filteredDirmngrConf(dirmngr).split(separator: "\n").map(String.init).filter { !$0.hasPrefix("#") }
        XCTAssertEqual(kept, ["keyserver hkps://keys.openpgp.org", "hkp-cacert /etc/ca.pem", "honor-http-proxy",
                              "http-proxy http://proxy:8080", "use-tor", "standard-resolver", "resolver-timeout 5"])
    }

    func testTemporaryHomeGetsFilteredConfig() throws {
        let k = try ring()
        try Data("keyserver hkps://keys.example.org\nkeyring /tmp/evil.kbx\n".utf8).write(to: k.home.appendingPathComponent("gpg.conf"))
        defer { try? FileManager.default.removeItem(at: k.home.appendingPathComponent("gpg.conf")) }
        let home = try IsolatedGPGHome.make(copyingConfigFrom: k.runner)
        defer { home.destroy(using: k.runner) }
        let written = try String(contentsOf: home.url.appendingPathComponent("gpg.conf"), encoding: .utf8)
        XCTAssertTrue(written.contains("keyserver hkps://keys.example.org"))
        XCTAssertFalse(written.contains("evil"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: home.url.appendingPathComponent("dirmngr.conf").path))
    }

    func testStaleTemporaryHomesAreRemoved() throws {
        let directory = try makeScratchDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let stale = directory.appendingPathComponent("sigil-fetch-old")
        let fresh = directory.appendingPathComponent("sigil-fetch-new")
        let other = directory.appendingPathComponent("other-old")
        for url in [stale, fresh, other] { try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true) }
        let twoHoursAgo = Date() - 7200
        for url in [stale, other] { try FileManager.default.setAttributes([.modificationDate: twoHoursAgo], ofItemAtPath: url.path) }
        let link = directory.appendingPathComponent("sigil-fetch-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: other)

        XCTAssertEqual(IsolatedGPGHome.removeStale(in: directory.path, gpgconf: nil), 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stale.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: fresh.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: other.path))
    }

    func testFetchedKeysAreImportedWithSelfSignaturesOnly() throws {
        let k = try ring()
        XCTAssertTrue(k.runner.baseArguments(allowingKeyLookup: true).joined(separator: " ")
            .contains("--import-options import-clean,self-sigs-only"))
        XCTAssertFalse(k.runner.baseArguments(allowingKeyLookup: false).contains("--import-options"))
    }
}
