import Foundation
import XCTest
@testable import SigilCore

final class GPGIntegrationTests: XCTestCase {
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
        guard let k = GPGIntegrationTests.keyring else {
            throw XCTSkip("no test keyring: \(GPGIntegrationTests.setupError ?? "unknown")")
        }
        return k
    }

    /// Writes generated PGP fixtures next to the keyring (for manual inspection while debugging).
    func save(_ data: Data, _ name: String) throws {
        try data.write(to: try ring().home.appendingPathComponent("\(name).eml"))
    }

    // MARK: Sign / verify

    func testSignThenDecoderVerifiesGood() throws {
        let k = try ring()
        let signed = try PGPMIMEEncoder.sign(message: sampleMessage(), signer: k.alice, gpg: k.runner)
        try save(signed, "pgp-mime-signed")
        XCTAssertEqual(PGPDetector.classify(messageData: signed), .pgpMimeSigned)

        // Outer headers kept.
        let msg = RFC822Message(data: signed)
        XCTAssertEqual(msg.header("Subject"), "Test message")
        XCTAssertEqual(msg.header("From"), "Alice <alice@example.org>")
        let ct = ContentType(parsing: MIMEEntity(data: msg.bodyEntity).headers["Content-Type"])
        XCTAssertEqual(ct.mimeType, "multipart/signed")
        XCTAssertTrue(ct.parameter("micalg")?.hasPrefix("pgp-sha") ?? false)
        XCTAssertTrue(Bytes.isSevenBitClean(signed))

        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: signed, gpg: k.runner))
        XCTAssertNil(outcome.error)
        XCTAssertTrue(outcome.signed)
        XCTAssertFalse(outcome.encrypted)
        XCTAssertFalse(outcome.partial)
        XCTAssertEqual(outcome.signers.count, 1)
        XCTAssertEqual(outcome.signers.first?.status, .good)
        XCTAssertEqual(outcome.signers.first?.fingerprint, k.alice)
        XCTAssertEqual(outcome.signers.first?.email, "alice@example.org")
        XCTAssertEqual(outcome.signers.first?.validity, .ultimate)

        let decoded = MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity)
        XCTAssertEqual(decoded.contentType.mimeType, "text/plain")
        XCTAssertTrue(decoded.text?.contains("Umlauts: äöü") ?? false)
        XCTAssertTrue(decoded.text?.contains("From the desk of Alice.   ") ?? false)
    }

    func testSignedPartVerifiesWithPlainGPGCLI() throws {
        let k = try ring()
        let signed = try PGPMIMEEncoder.sign(message: sampleMessage(), signer: k.alice, gpg: k.runner).string

        // Independent extraction (no SigilCore parsing): find the boundary and cut on CRLF--boundary.
        let boundary = try XCTUnwrap(signed.range(of: "boundary=\"([^\"]+)\"", options: .regularExpression)
            .map { String(signed[$0].dropFirst("boundary=\"".count).dropLast()) })
        let delimiter = "\r\n--\(boundary)"
        let firstDelim = try XCTUnwrap(signed.range(of: "--\(boundary)\r\n"))
        let afterFirst = signed[firstDelim.upperBound...]
        let secondDelim = try XCTUnwrap(afterFirst.range(of: delimiter))
        let signedPart = String(afterFirst[..<secondDelim.lowerBound])
        let sigPartStart = afterFirst[secondDelim.upperBound...]
        let sigBegin = try XCTUnwrap(sigPartStart.range(of: "-----BEGIN PGP SIGNATURE-----"))
        let sigEnd = try XCTUnwrap(sigPartStart.range(of: "-----END PGP SIGNATURE-----"))
        let signature = String(sigPartStart[sigBegin.lowerBound..<sigEnd.upperBound]) + "\r\n"

        let dir = k.home.appendingPathComponent("cli-\(UUID().uuidString.prefix(6))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let dataURL = dir.appendingPathComponent("part.eml"), sigURL = dir.appendingPathComponent("part.asc")
        try Data(signedPart.utf8).write(to: dataURL)
        try Data(signature.utf8).write(to: sigURL)
        let r = try k.gpg(["--status-fd", "2", "--verify", sigURL.path, dataURL.path])
        XCTAssertEqual(r.exitCode, 0, r.stderr)
        XCTAssertTrue(r.stderr.contains("[GNUPG:] GOODSIG"), r.stderr)
        XCTAssertTrue(r.stderr.contains(k.alice))
    }

    func testTamperedBodyReportsBadSignature() throws {
        let k = try ring()
        let signed = try PGPMIMEEncoder.sign(message: sampleMessage(), signer: k.alice, gpg: k.runner).string
        let tampered = Data(signed.replacingOccurrences(of: "this is a test", with: "this is a fest").utf8)
        XCTAssertNotEqual(tampered.string, signed)
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: tampered, gpg: k.runner))
        XCTAssertEqual(outcome.signers.map(\.status), [.bad])
        XCTAssertTrue(outcome.signed)
    }

    func testUnknownKeyReportsNoPublicKey() throws {
        let k = try ring()
        let malloryMail = sampleMessage().string.replacingOccurrences(of: "Alice <alice@example.org>", with: "Mallory <mallory@example.org>")
        let signed = try PGPMIMEEncoder.sign(message: Data(malloryMail.utf8), signer: k.mallory, gpg: k.otherRunner)
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: signed, gpg: k.runner))
        XCTAssertEqual(outcome.signers.count, 1)
        XCTAssertEqual(outcome.signers.first?.status, .noPublicKey)
        XCTAssertNotNil(outcome.signers.first?.keyID)
        XCTAssertNotNil(outcome.message)
    }

    func testPartialSignatureFlag() throws {
        let k = try ring()
        let signed = try PGPMIMEEncoder.sign(message: sampleMessage(), signer: k.alice, gpg: k.runner)
        // Mailing-list style: signed body wrapped into multipart/mixed with an unsigned footer.
        let msg = RFC822Message(data: signed)
        let footer = Data("Content-Type: text/plain; charset=us-ascii\r\n\r\n-- \r\nList footer, NOT signed\r\n".utf8)
        let mixed = MIMEBuilder.entity(headers: [("Content-Type", "multipart/mixed; boundary=\"list-b\"")],
                                       body: MIMEBuilder.multipartBody(parts: [msg.bodyEntity, footer], boundary: "list-b"))
        let wrapped = RFC822Message.combine(outerHeaders: msg.outerHeaders, bodyEntity: mixed)
        XCTAssertEqual(PGPDetector.classify(messageData: wrapped), .pgpMimeSigned)

        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: wrapped, gpg: k.runner))
        XCTAssertTrue(outcome.partial)
        XCTAssertEqual(outcome.signers.map(\.status), [.good])
        let decoded = MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity)
        XCTAssertEqual(decoded.contentType.mimeType, "multipart/mixed")
        XCTAssertEqual(decoded.leaves.count, 2)
        XCTAssertTrue(decoded.leaves[1].text?.contains("List footer") ?? false)
    }

    // MARK: Encrypt / decrypt

    func testEncryptDecryptRoundTrip() throws {
        let k = try ring()
        let encrypted = try PGPMIMEEncoder.encrypt(message: sampleMessage(), recipients: [k.bob], hidden: [],
                                                   signer: k.alice, gpg: k.runner)
        try save(encrypted, "pgp-mime-encrypted")
        XCTAssertEqual(PGPDetector.classify(messageData: encrypted), .pgpMimeEncrypted)
        XCTAssertFalse(encrypted.string.contains("Umlauts"))
        XCTAssertEqual(RFC822Message(data: encrypted).header("Subject"), "Test message")

        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: encrypted, gpg: k.runner))
        XCTAssertNil(outcome.error)
        XCTAssertTrue(outcome.encrypted)
        XCTAssertTrue(outcome.signed)
        XCTAssertFalse(outcome.partial)
        XCTAssertEqual(outcome.signers.map(\.status), [.good])
        XCTAssertEqual(outcome.signers.first?.fingerprint, k.alice)
        let decoded = RFC822Message(data: try XCTUnwrap(outcome.message))
        XCTAssertEqual(decoded.header("Subject"), "Test message")
        XCTAssertTrue(MIMEEntity(data: decoded.bodyEntity).text?.contains("Umlauts: äöü") ?? false)
    }

    func testHiddenRecipientOnlyEncryption() throws {
        let k = try ring()
        let encrypted = try PGPMIMEEncoder.encrypt(message: sampleMessage(), recipients: [], hidden: [k.bob],
                                                   signer: nil, gpg: k.runner)
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: encrypted, gpg: k.runner))
        XCTAssertTrue(outcome.encrypted)
        XCTAssertFalse(outcome.signed)
        XCTAssertNotNil(outcome.message)
    }

    func testSignedInsideEncrypted() throws {
        let k = try ring()
        let signed = try PGPMIMEEncoder.sign(message: sampleMessage(), signer: k.alice, gpg: k.runner)
        let msg = RFC822Message(data: signed)
        let ciphertext = try k.runner.encrypt(msg.bodyEntity, recipients: [k.bob], hiddenRecipients: [], signerFingerprint: nil)
        let message = RFC822Message.combine(outerHeaders: msg.outerHeaders,
                                            bodyEntity: MIMEBuilder.multipartEncrypted(armoredCiphertext: ciphertext))
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: message, gpg: k.runner))
        XCTAssertTrue(outcome.encrypted)
        XCTAssertEqual(outcome.signers.map(\.status), [.good])
        XCTAssertFalse(outcome.partial)
        let body = MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity)
        XCTAssertEqual(body.contentType.mimeType, "text/plain")
    }

    func testTamperedCiphertextGivesErrorAndNoPlaintext() throws {
        let k = try ring()
        let encrypted = try PGPMIMEEncoder.encrypt(message: sampleMessage(), recipients: [k.bob], hidden: [],
                                                   signer: nil, gpg: k.runner)
        // Flip a character in the middle of the armored payload.
        var lines = encrypted.string.components(separatedBy: "\r\n")
        let begin = try XCTUnwrap(lines.firstIndex(of: "-----BEGIN PGP MESSAGE-----"))
        let end = try XCTUnwrap(lines.firstIndex(of: "-----END PGP MESSAGE-----"))
        let target = (begin + end) / 2 + 1
        var chars = Array(lines[target])
        let mid = chars.count / 2
        chars[mid] = chars[mid] == "A" ? "B" : "A"
        lines[target] = String(chars)
        let tampered = Data(lines.joined(separator: "\r\n").utf8)

        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: tampered, gpg: k.runner))
        XCTAssertNil(outcome.message)
        XCTAssertNotNil(outcome.error)
        XCTAssertTrue(outcome.encrypted)
        XCTAssertFalse(outcome.signed)

        // Directly at the runner level: an error, never plaintext.
        let armored = MIMEEntity(data: RFC822Message(data: tampered).bodyEntity).children[1].decodedBody
        XCTAssertThrowsError(try k.runner.decrypt(armored))
    }

    func testMissingRecipientKeyError() throws {
        let k = try ring()
        XCTAssertThrowsError(try PGPMIMEEncoder.encrypt(message: sampleMessage(), recipients: ["nobody@example.org"],
                                                        hidden: [], signer: nil, gpg: k.runner)) { error in
            guard case let .invalidRecipients(specs)? = error as? GPGError else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertEqual(specs.first?.spec, "nobody@example.org")
        }
        let service = GPGService(runner: k.runner)
        let status = try service.encodingStatus(from: "Alice <alice@example.org>",
                                                recipients: ["Bob <bob@example.org>", "nobody@example.org"])
        XCTAssertEqual(status.missingRecipients, ["nobody@example.org"])
        XCTAssertTrue(status.canSign)
        XCTAssertEqual(status.signerFingerprint, k.alice)
        XCTAssertFalse(status.canEncrypt)
        XCTAssertThrowsError(try service.encode(message: sampleMessage(), sign: true, encrypt: true, from: "alice@example.org",
                                                recipients: ["nobody@example.org"], hiddenRecipients: []))
    }

    // MARK: Inline PGP

    func testInlineSigned() throws {
        let k = try ring()
        let r = try k.gpg(["--local-user", k.alice, "--clearsign"], stdin: Data("Hello inline world\n".utf8))
        XCTAssertEqual(r.exitCode, 0, r.stderr)
        let body = LineEndings.toCRLF(r.stdout).string
        let message = sampleMessage(body: body, contentType: "text/plain; charset=us-ascii", cte: "7bit")
        try save(message, "inline-signed")
        XCTAssertEqual(PGPDetector.classify(messageData: message), .inline)

        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: message, gpg: k.runner))
        XCTAssertEqual(outcome.classification, .inline)
        XCTAssertEqual(outcome.signers.map(\.status), [.good])
        XCTAssertFalse(outcome.partial)
        XCTAssertFalse(outcome.encrypted)
        let text = try XCTUnwrap(MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity).text)
        XCTAssertTrue(text.contains("Hello inline world"))
        XCTAssertFalse(text.contains("BEGIN PGP"))

        // Unsigned text around the block makes it partial.
        let mixed = sampleMessage(body: "Unsigned intro\r\n" + body, contentType: "text/plain", cte: "7bit")
        let partial = try XCTUnwrap(PGPMIMEDecoder.decode(message: mixed, gpg: k.runner))
        XCTAssertTrue(partial.partial)
        XCTAssertEqual(partial.signers.map(\.status), [.good])
    }

    func testInlineEncrypted() throws {
        let k = try ring()
        let r = try k.gpg(["--armor", "--encrypt", "--recipient", k.bob], stdin: Data("Secret inline Grüße\n".utf8))
        XCTAssertEqual(r.exitCode, 0, r.stderr)
        let message = sampleMessage(body: LineEndings.toCRLF(r.stdout).string, contentType: "text/plain", cte: "7bit")
        try save(message, "inline-encrypted")
        XCTAssertEqual(PGPDetector.classify(messageData: message), .inline)

        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: message, gpg: k.runner))
        XCTAssertTrue(outcome.encrypted)
        XCTAssertFalse(outcome.signed)
        let text = try XCTUnwrap(MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity).text)
        XCTAssertEqual(text.trimmingCharacters(in: .whitespacesAndNewlines), "Secret inline Grüße")
    }

    // MARK: Non-PGP and service

    func testNonPGPReturnsNil() throws {
        let k = try ring()
        XCTAssertNil(PGPMIMEDecoder.decode(message: try Fixtures.data("plain"), gpg: k.runner))
        XCTAssertNil(PGPMIMEDecoder.decode(message: try Fixtures.data("nested-multipart"), gpg: k.runner))
        XCTAssertNil(PGPMIMEDecoder.decode(message: try Fixtures.data("qp-8bit"), gpg: k.runner))
    }

    func testRunnerListKeys() throws {
        let k = try ring()
        let pub = try k.runner.listKeys(secret: false)
        XCTAssertEqual(Set(pub.map(\.fingerprint)), [k.alice, k.bob])
        XCTAssertTrue(pub.allSatisfy { $0.capabilities.sign && $0.capabilities.encrypt && $0.isUsable })
        let sec = try k.runner.listKeys(secret: true, patterns: ["<alice@example.org>"])
        XCTAssertEqual(sec.map(\.fingerprint), [k.alice])
        XCTAssertTrue(sec[0].isSecret)
        XCTAssertEqual(try k.runner.listKeys(secret: false, patterns: ["<nobody@example.org>"]).count, 0)
        XCTAssertTrue(try k.runner.version().contains("GnuPG"))
    }

    func testServiceXPCSurface() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner)
        var version = ""
        service.ping { version = $0 }
        XCTAssertTrue(version.hasPrefix("gpg (GnuPG)"))

        var keysJSON: Data?
        service.listKeys(secret: false) { d, e in keysJSON = d; XCTAssertNil(e) }
        let keys = try SigilJSON.decoder().decode([KeyInfo].self, from: try XCTUnwrap(keysJSON))
        XCTAssertEqual(keys.count, 2)

        var statusJSON: Data?
        service.encodingStatus(from: "alice@example.org", recipients: ["bob@example.org"]) { d, _ in statusJSON = d }
        let status = try SigilJSON.decoder().decode(EncodingStatus.self, from: try XCTUnwrap(statusJSON))
        XCTAssertEqual(status, EncodingStatus(canSign: true, signerFingerprint: k.alice, missingRecipients: [], canEncrypt: true,
                                              unverifiedRecipients: []))

        var encoded: Data?
        service.encode(message: sampleMessage(), sign: true, encrypt: true, from: "Alice <alice@example.org>",
                       recipients: ["Bob <bob@example.org>"], hiddenRecipients: []) { d, e in encoded = d; XCTAssertNil(e) }
        let enc = try XCTUnwrap(encoded)
        XCTAssertEqual(PGPDetector.classify(messageData: enc), .pgpMimeEncrypted)

        var decodedJSON: Data?
        service.decode(message: enc, interactive: false, allowMixed: false) { d, e in decodedJSON = d; XCTAssertNil(e) }
        let outcome = try SigilJSON.decoder().decode(DecodeOutcome.self, from: try XCTUnwrap(decodedJSON))
        XCTAssertTrue(outcome.encrypted)
        XCTAssertEqual(outcome.signers.map(\.status), [.good])
        XCTAssertTrue(MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity).text?.contains("Umlauts") ?? false)

        // Encrypted to self as well: the ciphertext lists two recipients.
        let armored = MIMEEntity(data: RFC822Message(data: enc).bodyEntity).children[1].decodedBody
        XCTAssertEqual(try k.runner.decrypt(armored).encryptedTo.count, 2)

        var nilData: Data? = Data(), nilError: String? = ""
        service.decode(message: try Fixtures.data("plain"), interactive: false, allowMixed: false) { d, e in nilData = d; nilError = e }
        XCTAssertNil(nilData)
        XCTAssertNil(nilError)

        let missing = GPGService(runner: nil)
        var err = ""
        missing.ping { err = $0 }
        XCTAssertTrue(err.hasPrefix("error:"))
    }
}
