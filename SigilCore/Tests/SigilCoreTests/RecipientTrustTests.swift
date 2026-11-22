import Foundation
import XCTest
@testable import SigilCore

/// Recipient trust rule: usable keys of unknown validity are encrypted to (and reported as unverified);
/// expired and revoked keys stay missing; signature results keep gpg's real validity.
final class RecipientTrustTests: XCTestCase {
    /// Alice owns `home` (ultimately trusted). Carol, Dave (expired) and Erin (revoked) are generated in
    /// `sourceHome` and imported into `home` without being certified.
    struct TrustKeyring: Sendable {
        let home: URL
        let sourceHome: URL
        let alice: String
        let carol: String
        let dave: String
        let erin: String

        var runner: GPGRunner { GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: home, timeout: 30) }
        var sourceRunner: GPGRunner {
            GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: sourceHome, timeout: 30)
        }
    }

    nonisolated(unsafe) static var keyring: TrustKeyring?
    nonisolated(unsafe) static var setupError: String?

    override class func setUp() {
        super.setUp()
        do { keyring = try makeKeyring() } catch { setupError = "\(error)" }
    }

    override class func tearDown() {
        if let keyring {
            for home in [keyring.home, keyring.sourceHome] {
                _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", home.path, "--kill", "all"])
                try? FileManager.default.removeItem(at: home)
            }
        }
        keyring = nil
        super.tearDown()
    }

    static func gpg(_ args: [String], home: URL, stdin: Data? = nil) throws -> CLIResult {
        let result = try runCLI(TestKeyring.gpgPath, ["--homedir", home.path, "--batch", "--no-tty"] + args, stdin: stdin)
        guard result.exitCode == 0 else {
            throw NSError(domain: "RecipientTrustTests", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "gpg \(args.joined(separator: " ")): \(result.stderr)"])
        }
        return result
    }

    static func makeKeyring() throws -> TrustKeyring {
        let home = try TestKeyring.makeHome()
        let sourceHome = try TestKeyring.makeHome()
        let alice = try TestKeyring.generate("Alice <alice@example.org>", in: home)
        let carol = try TestKeyring.generate("Carol <carol@example.org>", in: sourceHome)
        let erin = try TestKeyring.generate("Erin <erin@example.org>", in: sourceHome)

        // Dave's key was created in 2020 and expired in 2021.
        _ = try gpg(["--faked-system-time", "20200101T000000!", "--pinentry-mode", "loopback", "--passphrase", "",
                     "--quick-gen-key", "Dave <dave@example.org>", "default", "default", "1y"], home: sourceHome)
        let daveListing = try gpg(["--with-colons", "--list-keys", "<dave@example.org>"], home: sourceHome).stdout.string
        let dave = try XCTUnwrap(daveListing.split(separator: "\n").first { $0.hasPrefix("fpr:") }
            .map { String($0.split(separator: ":", omittingEmptySubsequences: false)[9]) })

        let exported = try gpg(["--armor", "--export", carol, dave, erin], home: sourceHome).stdout
        _ = try gpg(["--import"], home: home, stdin: exported)

        // Revoke Erin in Alice's keyring with the revocation certificate gpg created at key generation.
        let revocationURL = sourceHome.appendingPathComponent("openpgp-revocs.d/\(erin).rev")
        let revocation = try String(contentsOf: revocationURL, encoding: .utf8)
            .replacingOccurrences(of: ":-----BEGIN PGP PUBLIC KEY BLOCK-----", with: "-----BEGIN PGP PUBLIC KEY BLOCK-----")
        _ = try gpg(["--import"], home: home, stdin: Data(revocation.utf8))

        return TrustKeyring(home: home, sourceHome: sourceHome, alice: alice, carol: carol, dave: dave, erin: erin)
    }

    func ring() throws -> TrustKeyring {
        guard let keyring = RecipientTrustTests.keyring else {
            throw XCTSkip("no trust keyring: \(RecipientTrustTests.setupError ?? "unknown")")
        }
        return keyring
    }

    func message(from: String, to: String) -> Data {
        Data(sampleMessage().string
            .replacingOccurrences(of: "From: Alice <alice@example.org>", with: "From: \(from)")
            .replacingOccurrences(of: "To: Bob <bob@example.org>", with: "To: \(to)").utf8)
    }

    func testImportedUncertifiedKeyIsUsableAndUnverified() throws {
        let keyring = try ring()
        let carolKey = try XCTUnwrap(keyring.runner.listKeys(secret: false, patterns: [keyring.carol]).first)
        XCTAssertFalse(["f", "u"].contains(carolKey.userIDs.first?.validity ?? ""),
                       "Carol must not be certified, got \(carolKey.userIDs.first?.validity ?? "nil")")

        let service = GPGService(runner: keyring.runner)
        let status = try service.encodingStatus(from: "Alice <alice@example.org>",
                                                recipients: ["Carol <carol@example.org>", "alice@example.org"])
        XCTAssertEqual(status, EncodingStatus(canSign: true, signerFingerprint: keyring.alice, missingRecipients: [],
                                              canEncrypt: true, unverifiedRecipients: ["Carol <carol@example.org>"]))

        let encoded = try service.encode(message: message(from: "Alice <alice@example.org>", to: "Carol <carol@example.org>"),
                                         sign: true, encrypt: true, from: "Alice <alice@example.org>",
                                         recipients: ["Carol <carol@example.org>"], hiddenRecipients: [])
        XCTAssertEqual(PGPDetector.classify(messageData: encoded), .pgpMimeEncrypted)

        // Carol can read it in her own keyring.
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: encoded, gpg: keyring.sourceRunner))
        XCTAssertNil(outcome.error)
        XCTAssertTrue(outcome.encrypted)
        XCTAssertTrue(MIMEEntity(data: RFC822Message(data: try XCTUnwrap(outcome.message)).bodyEntity).text?
            .contains("Umlauts") ?? false)
    }

    func testUserIDRecipientSpecKeepsGPGTrustChecks() throws {
        // The trust override only applies to fingerprints we resolved; a user ID spec still needs a valid key.
        let keyring = try ring()
        XCTAssertThrowsError(try keyring.runner.encrypt(Data("x".utf8), recipients: ["carol@example.org"],
                                                        hiddenRecipients: [], signerFingerprint: nil))
        XCTAssertNoThrow(try keyring.runner.encrypt(Data("x".utf8), recipients: [keyring.carol],
                                                    hiddenRecipients: [], signerFingerprint: nil))
    }

    func testExpiredAndRevokedKeysAreMissing() throws {
        let keyring = try ring()
        let service = GPGService(runner: keyring.runner)
        let status = try service.encodingStatus(from: "alice@example.org",
                                                recipients: ["Dave <dave@example.org>", "erin@example.org", "carol@example.org"])
        XCTAssertEqual(status.missingRecipients, ["Dave <dave@example.org>", "erin@example.org"])
        XCTAssertEqual(status.unverifiedRecipients, ["carol@example.org"])
        XCTAssertFalse(status.canEncrypt)

        XCTAssertThrowsError(try service.encode(message: sampleMessage(), sign: false, encrypt: true, from: "alice@example.org",
                                                recipients: ["dave@example.org"], hiddenRecipients: [])) { error in
            XCTAssertEqual(error as? GPGError, .missingKeys(["dave@example.org"]))
        }
        XCTAssertThrowsError(try service.encode(message: sampleMessage(), sign: false, encrypt: true, from: "alice@example.org",
                                                recipients: [], hiddenRecipients: ["erin@example.org"])) { error in
            XCTAssertEqual(error as? GPGError, .missingKeys(["erin@example.org"]))
        }

        // Even with the per-call trust override, gpg itself refuses expired and revoked fingerprints.
        for fingerprint in [keyring.dave, keyring.erin] {
            XCTAssertThrowsError(try keyring.runner.encrypt(Data("x".utf8), recipients: [fingerprint],
                                                            hiddenRecipients: [], signerFingerprint: nil)) { error in
                guard case .invalidRecipients = error as? GPGError else { return XCTFail("unexpected error \(error)") }
            }
        }
    }

    func testSignatureByUncertifiedKeyReportsRealValidity() throws {
        let keyring = try ring()
        let signed = try PGPMIMEEncoder.sign(message: message(from: "Carol <carol@example.org>", to: "Alice <alice@example.org>"),
                                             signer: keyring.carol, gpg: keyring.sourceRunner)
        let outcome = try XCTUnwrap(PGPMIMEDecoder.decode(message: signed, gpg: keyring.runner))
        XCTAssertEqual(outcome.signers.map(\.status), [.good])
        XCTAssertEqual(outcome.signers.first?.fingerprint, keyring.carol)
        XCTAssertEqual(outcome.signers.first?.validity, .undefined)
    }
}
