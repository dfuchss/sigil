import Foundation
import XCTest
@testable import SigilCore

/// Sigil only lists and matches keys through user IDs with an email address; signatures by other keys are
/// still verified and shown.
final class EmailUserIDTests: XCTestCase {
    nonisolated(unsafe) static var home: URL?
    nonisolated(unsafe) static var nameOnly = ""
    nonisolated(unsafe) static var mixed = ""
    nonisolated(unsafe) static var setupError: String?

    override class func setUp() {
        super.setUp()
        do {
            let h = try TestKeyring.makeHome()
            home = h
            nameOnly = try TestKeyring.generate("Nameless Key", in: h)
            mixed = try TestKeyring.generate("Dora <Dora@Example.org>", in: h)
            let added = try runCLI(TestKeyring.gpgPath, ["--homedir", h.path, "--batch", "--no-tty", "--pinentry-mode",
                                                         "loopback", "--passphrase", "", "--quick-add-uid", mixed, "Just A Name"])
            if added.exitCode != 0 { setupError = added.stderr }
        } catch {
            setupError = "\(error)"
        }
    }

    override class func tearDown() {
        if let home {
            _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", home.path, "--kill", "all"])
            try? FileManager.default.removeItem(at: home)
        }
        super.tearDown()
    }

    func runner() throws -> GPGRunner {
        guard let home = EmailUserIDTests.home, EmailUserIDTests.setupError == nil else {
            throw XCTSkip("no test keyring: \(EmailUserIDTests.setupError ?? "unknown")")
        }
        return GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: home, timeout: 30)
    }

    func testFilterDropsUserIDsAndKeysWithoutEmail() {
        let text = """
            pub:u:255:22:AAAAAAAAAAAAAAAA:1:::u:::scESC:::::ed25519:::0:
            fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:
            uid:u::::1::X::Only A Name::::::::::0:
            pub:u:255:22:BBBBBBBBBBBBBBBB:1:::u:::scESC:::::ed25519:::0:
            fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:
            uid:u::::1::Y::Some Name::::::::::0:
            uid:u::::1::Z::Erin <erin@example.org>::::::::::0:
            uid:u::::1::W::bare@example.org::::::::::0:
            """
        let keys = KeyInfo.withEmailUserIDsOnly(GPGColonsParser.parseKeys(text))
        XCTAssertEqual(keys.map(\.fingerprint), ["BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"])
        XCTAssertEqual(keys[0].userIDs.map(\.uid), ["Erin <erin@example.org>", "bare@example.org"])
    }

    func testNameOnlyKeyIsNeverListedOrChosen() throws {
        let gpg = try runner()
        let all = try gpg.listKeys(secret: false)
        XCTAssertFalse(all.contains { $0.fingerprint == EmailUserIDTests.nameOnly })
        XCTAssertEqual(try gpg.listKeys(secret: false, patterns: [EmailUserIDTests.nameOnly]).count, 0)
        XCTAssertEqual(try gpg.listKeys(secret: true, patterns: ["Nameless"]).count, 0)

        let service = GPGService(runner: gpg)
        for spec in ["Nameless Key", EmailUserIDTests.nameOnly, "Nameless Key <>"] {
            XCTAssertNil(try service.resolveRecipient(spec), spec)
            XCTAssertNil(try service.resolveSigner(from: spec), spec)
        }
        let status = try service.encodingStatus(from: "Nameless Key", recipients: ["Nameless Key"])
        XCTAssertFalse(status.canSign)
        XCTAssertFalse(status.canEncrypt)
        XCTAssertEqual(status.missingRecipients, ["Nameless Key"])
    }

    func testMixedKeyKeepsOnlyEmailUserIDsAndMatchesCaseInsensitively() throws {
        let gpg = try runner()
        let keys = try gpg.listKeys(secret: false, patterns: [EmailUserIDTests.mixed])
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].userIDs.map(\.uid), ["Dora <Dora@Example.org>"])
        XCTAssertEqual(keys[0].emails, ["dora@example.org"])

        let service = GPGService(runner: gpg)
        XCTAssertEqual(try service.resolveRecipient("DORA@example.ORG")?.fingerprint, EmailUserIDTests.mixed)
        XCTAssertEqual(try service.resolveSigner(from: "Dora <dora@EXAMPLE.org>")?.fingerprint, EmailUserIDTests.mixed)
        XCTAssertNil(try service.resolveRecipient("Just A Name"))
    }

    /// Sending never signs with or encrypts to a name-only key, whatever spec Mail hands over.
    func testEncodeNeverUsesNameOnlyKey() throws {
        let service = GPGService(runner: try runner())
        for spec in ["Nameless Key", EmailUserIDTests.nameOnly, "Nameless Key <\(EmailUserIDTests.nameOnly)>"] {
            XCTAssertThrowsError(try service.encode(message: sampleMessage(), sign: true, encrypt: false, from: spec,
                                                    recipients: ["dora@example.org"], hiddenRecipients: []), spec)
            for (to, bcc) in [([spec], [String]()), (["dora@example.org"], [spec])] {
                XCTAssertThrowsError(try service.encode(message: sampleMessage(), sign: false, encrypt: true,
                                                        from: "dora@example.org", recipients: to, hiddenRecipients: bcc)) {
                    guard case .missingKeys? = $0 as? GPGError else { return XCTFail("unexpected error \($0)") }
                }
            }
        }
    }

    func testSignatureByNameOnlyKeyIsShownButDoesNotMatchSender() throws {
        let gpg = try runner()
        let signed = try PGPMIMEEncoder.sign(message: sampleMessage(), signer: EmailUserIDTests.nameOnly, gpg: gpg)
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: signed, gpg: gpg))
        XCTAssertTrue(outcome.signed)
        XCTAssertEqual(outcome.signers.count, 1)
        let signer = outcome.signers[0]
        XCTAssertEqual(signer.status, .good)
        XCTAssertEqual(signer.fingerprint, EmailUserIDTests.nameOnly)
        XCTAssertNotNil(signer.keyID)
        XCTAssertNil(signer.email)
        XCTAssertEqual(signer.matchesSender, false)

        // A good signature without the From address is a signature problem: no Mail badge, a banner instead.
        let p = DecodePresentation.make(outcome: outcome, original: signed)
        XCTAssertTrue(p.signers.isEmpty)
        XCTAssertTrue(p.banner?.title.hasPrefix("Signed by a different address: Nameless Key") ?? false, "\(String(describing: p.banner))")
        XCTAssertTrue(p.banner?.title.hasSuffix("is not the sender alice@example.org.") ?? false)
        XCTAssertNotNil(p.signingError)
        let shown = SignerPresentation(signer: signer, partial: false)
        XCTAssertEqual(shown.emailAddresses, [])
        XCTAssertTrue(shown.label.hasPrefix("Nameless Key, key 0x\(try XCTUnwrap(signer.keyID))"), shown.label)
        XCTAssertTrue(shown.label.contains("not the sender's address"), shown.label)
        let details = SignerDetails(context: try XCTUnwrap(SignerContext.decode(shown.context)))
        XCTAssertEqual(details.rows.first { $0.label == "Fingerprint" }?.value, Fingerprint.grouped(EmailUserIDTests.nameOnly))
        XCTAssertTrue(details.rows.contains { $0.label == "Sender" && $0.value.contains("no email user ID") })
    }

    func testSignatureByMixedKeyMatchesSender() throws {
        let gpg = try runner()
        let message = sampleMessage().string.replacingOccurrences(of: "From: Alice <alice@example.org>",
                                                                   with: "From: Dora <DORA@example.org>")
        let signed = try PGPMIMEEncoder.sign(message: Data(message.utf8), signer: EmailUserIDTests.mixed, gpg: gpg)
        let signer = try XCTUnwrap(PGPMIMEDecoder.decode(message: signed, gpg: gpg)?.signers.first)
        XCTAssertEqual(signer.email, "dora@example.org")
        XCTAssertEqual(signer.matchesSender, true)
        XCTAssertFalse(SignerPresentation(signer: signer, partial: false).label.contains("not the sender"))
    }
}
