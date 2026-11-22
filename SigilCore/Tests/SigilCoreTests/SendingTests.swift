import Foundation
import XCTest
@testable import SigilCore

/// Sending path as the Mail extension uses it: `GPGService.encode` with Mail's LF-only input.
final class SendingTests: XCTestCase {
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
        guard let k = SendingTests.keyring else {
            throw XCTSkip("no test keyring: \(SendingTests.setupError ?? "unknown")")
        }
        return k
    }

    /// A message as Mail hands it to `encode`: LF line endings, 8-bit text, trailing whitespace, a "From " line.
    static let lfPlainMessage = LineEndings.toLF(sampleMessage(
        body: "Hello Bob,\r\n\r\nUmlauts: \u{00e4}\u{00f6}\u{00fc}.\r\nFrom here on, trailing blanks:   \r\n"
            + String(repeating: "long line ", count: 12) + "\r\n"))

    static let lfAlternativeMessage = Data("""
        From: Alice <alice@example.org>
        To: Bob <bob@example.org>
        Subject: Alternative
        Message-Id: <alt-1@example.org>
        Mime-Version: 1.0 (Mac OS X Mail 27.0)
        Content-Type: multipart/alternative; boundary="Apple-Mail=_ABC"

        --Apple-Mail=_ABC
        Content-Transfer-Encoding: quoted-printable
        Content-Type: text/plain; charset=utf-8

        Gr=C3=BC=C3=9Fe
        From Alice

        --Apple-Mail=_ABC
        Content-Transfer-Encoding: 7bit
        Content-Type: text/html; charset=us-ascii

        <html><body>Hi</body></html>
        --Apple-Mail=_ABC--

        """.utf8)

    /// Cuts a multipart/signed message into the signed part and the armored signature without SigilCore parsing.
    static func split(signed message: String) throws -> (part: String, signature: String) {
        let boundary = try XCTUnwrap(message.range(of: "boundary=\"([^\"]+)\"", options: .regularExpression)
            .map { String(message[$0].dropFirst("boundary=\"".count).dropLast()) })
        let firstDelimiter = try XCTUnwrap(message.range(of: "--\(boundary)\r\n"))
        let afterFirst = message[firstDelimiter.upperBound...]
        let secondDelimiter = try XCTUnwrap(afterFirst.range(of: "\r\n--\(boundary)"))
        let signaturePart = afterFirst[secondDelimiter.upperBound...]
        let begin = try XCTUnwrap(signaturePart.range(of: "-----BEGIN PGP SIGNATURE-----"))
        let end = try XCTUnwrap(signaturePart.range(of: "-----END PGP SIGNATURE-----"))
        return (String(afterFirst[..<secondDelimiter.lowerBound]), String(signaturePart[begin.lowerBound..<end.upperBound]) + "\r\n")
    }

    func verifyWithGPGCLI(_ message: Data, _ k: TestKeyring) throws {
        let (part, signature) = try SendingTests.split(signed: message.string)
        let dir = k.home.appendingPathComponent("send-\(UUID().uuidString.prefix(6))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let partURL = dir.appendingPathComponent("part.eml"), signatureURL = dir.appendingPathComponent("part.asc")
        try Data(part.utf8).write(to: partURL)
        try Data(signature.utf8).write(to: signatureURL)
        let r = try k.gpg(["--status-fd", "2", "--verify", signatureURL.path, partURL.path])
        XCTAssertEqual(r.exitCode, 0, r.stderr)
        XCTAssertTrue(r.stderr.contains("[GNUPG:] GOODSIG"), r.stderr)
        XCTAssertTrue(r.stderr.contains(k.alice), r.stderr)
    }

    /// Key IDs of the public-key encrypted session key packets, from `gpg --list-packets` in a keyring that
    /// cannot decrypt (so gpg only lists).
    func sessionKeyRecipients(_ encrypted: Data, _ k: TestKeyring) throws -> [String] {
        let armored = MIMEEntity(data: RFC822Message(data: encrypted).bodyEntity).children[1].decodedBody
        let r = try k.gpg(["--list-packets"], home: k.otherHome, stdin: armored)
        return r.stdout.string.split(separator: "\n").filter { $0.hasPrefix(":pubkey enc packet:") }.compactMap { line in
            line.range(of: "keyid ").map { String(line[$0.upperBound...].prefix(16)) }
        }
    }

    func encryptionSubkeyID(_ fingerprint: String, _ k: TestKeyring) throws -> String {
        let r = try k.gpg(["--with-colons", "--list-keys", fingerprint])
        let subkeys = r.stdout.string.split(separator: "\n").filter { $0.hasPrefix("sub:") }
            .map { $0.split(separator: ":", omittingEmptySubsequences: false) }
        let encryptionSubkey = try XCTUnwrap(subkeys.first { $0[11].contains("e") })
        return String(encryptionSubkey[4])
    }

    // MARK: Tests

    func testLFInputSignedOutputVerifiesAfterTransportLineEndingChanges() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner)
        for input in [SendingTests.lfPlainMessage, SendingTests.lfAlternativeMessage] {
            XCTAssertTrue(LineEndings.usesBareLF(input))
            let signed = try service.encode(message: input, sign: true, encrypt: false, from: "Alice <alice@example.org>",
                                            recipients: ["Bob <bob@example.org>"], hiddenRecipients: [])
            XCTAssertEqual(PGPDetector.classify(messageData: signed), .pgpMimeSigned)
            XCTAssertTrue(Bytes.isSevenBitClean([UInt8](RFC822Message(data: signed).bodyEntity)), "body must be 7-bit")
            try verifyWithGPGCLI(signed, k)
            // What Mail stores (LF) and what SMTP carries (CRLF) again.
            let transported = LineEndings.toCRLF(LineEndings.toLF(signed))
            XCTAssertEqual(transported, signed, "the output is entirely CRLF, so the round trip is lossless")
            try verifyWithGPGCLI(transported, k)
            // Sigil's own decoder accepts both forms.
            for form in [signed, LineEndings.toLF(signed)] {
                let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: form, gpg: k.runner))
                XCTAssertEqual(outcome.signers.map(\.status), [.good])
            }
        }
    }

    func testLFInputEncryptedRoundTrip() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner)
        let encrypted = try service.encode(message: SendingTests.lfAlternativeMessage, sign: true, encrypt: true,
                                           from: "alice@example.org", recipients: ["bob@example.org"], hiddenRecipients: [])
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: LineEndings.toLF(encrypted), gpg: k.runner))
        XCTAssertTrue(outcome.encrypted)
        XCTAssertEqual(outcome.signers.map(\.status), [.good])
        let body = MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity)
        XCTAssertEqual(body.contentType.mimeType, "multipart/alternative")
        XCTAssertTrue(body.children[0].text?.contains("Grüße") ?? false)
    }

    func testBccIsHiddenRecipient() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner)
        let encrypted = try service.encode(message: SendingTests.lfPlainMessage, sign: false, encrypt: true,
                                           from: "alice@example.org", recipients: [],
                                           hiddenRecipients: ["Bob <bob@example.org>"])
        let keyIDs = try sessionKeyRecipients(encrypted, k)
        XCTAssertEqual(keyIDs.sorted(), ["0000000000000000", try encryptionSubkeyID(k.alice, k)].sorted())
        XCTAssertFalse(keyIDs.contains(try encryptionSubkeyID(k.bob, k)))
        XCTAssertNotNil(PGPMIMEDecoder.decode(message: encrypted, gpg: k.runner)?.message)
    }

    func testAlwaysEncryptedToSelf() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner)
        for sign in [false, true] {
            let encrypted = try service.encode(message: SendingTests.lfPlainMessage, sign: sign, encrypt: true,
                                               from: "Alice <alice@example.org>", recipients: ["bob@example.org"],
                                               hiddenRecipients: [])
            XCTAssertEqual(try sessionKeyRecipients(encrypted, k).sorted(),
                           [try encryptionSubkeyID(k.alice, k), try encryptionSubkeyID(k.bob, k)].sorted())
        }
    }

    func testMissingKeyGivesErrorAndNoOutput() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner)
        for (to, bcc) in [(["nobody@example.org"], [String]()), (["bob@example.org"], ["nobody@example.org"])] {
            for sign in [false, true] {
                var output: Data?
                var error: String?
                service.encode(message: SendingTests.lfPlainMessage, sign: sign, encrypt: true, from: "alice@example.org",
                               recipients: to, hiddenRecipients: bcc) { output = $0; error = $1 }
                XCTAssertNil(output)
                XCTAssertTrue(error?.contains("nobody@example.org") ?? false, error ?? "no error")
            }
        }
        // Signing without a secret key for the sender fails the same way.
        var output: Data?
        var error: String?
        service.encode(message: SendingTests.lfPlainMessage, sign: true, encrypt: false, from: "nobody@example.org",
                       recipients: ["alice@example.org"], hiddenRecipients: []) { output = $0; error = $1 }
        XCTAssertNil(output)
        XCTAssertNotNil(error)
    }

    func testNeitherSignNorEncryptReturnsInputUnchanged() throws {
        let k = try ring()
        let service = GPGService(runner: k.runner)
        XCTAssertEqual(try service.encode(message: SendingTests.lfPlainMessage, sign: false, encrypt: false,
                                          from: "alice@example.org", recipients: ["nobody@example.org"],
                                          hiddenRecipients: []), SendingTests.lfPlainMessage)
    }

    func testToLFKeepsBareCR() {
        XCTAssertEqual(LineEndings.toLF(Data("a\r\nb\rc\r".utf8)), Data("a\nb\rc\r".utf8))
        XCTAssertFalse(LineEndings.usesBareLF(Data("a\r\n".utf8)))
    }
}
