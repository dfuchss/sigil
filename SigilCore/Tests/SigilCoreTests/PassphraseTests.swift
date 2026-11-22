import Foundation
import XCTest
@testable import SigilCore

/// Non-interactive decryption with a passphrase-protected key. Never runs an interactive decrypt (that would
/// open a pinentry window).
final class PassphraseTests: XCTestCase {
    func testNonInteractiveDecodeNeedsCachedPassphrase() throws {
        let home = try TestKeyring.makeHome()
        defer {
            _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", home.path, "--kill", "all"])
            try? FileManager.default.removeItem(at: home)
        }
        let uid = "Carol <carol@example.org>"
        let generated = try runCLI(TestKeyring.gpgPath, ["--homedir", home.path, "--batch", "--no-tty",
                                                         "--pinentry-mode", "loopback", "--passphrase", "carol-secret",
                                                         "--quick-gen-key", uid, "default", "default", "never"])
        XCTAssertEqual(generated.exitCode, 0, generated.stderr)
        let runner = GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: home, timeout: 30)
        let carol = try XCTUnwrap(try runner.listKeys(secret: false, patterns: [uid]).first?.fingerprint)
        // Generating cached the passphrase; start from a cold agent.
        _ = try runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", home.path, "--reload", "gpg-agent"])

        let encrypted = try PGPMIMEEncoder.encrypt(message: sampleMessage(), recipients: [carol], signer: nil, gpg: runner)
        let started = Date()
        let locked = try XCTUnwrap(PGPMIMEDecoder.decode(message: encrypted, gpg: runner, interactive: false))
        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "non-interactive decode must fail fast")
        XCTAssertTrue(locked.needsPassphrase)
        XCTAssertTrue(locked.encrypted)
        XCTAssertNil(locked.message)
        let presentation = DecodePresentation.make(outcome: locked, original: encrypted)
        XCTAssertEqual(presentation.banner?.actionTitle, "Decrypt")
        XCTAssertEqual(presentation.rawData, encrypted)

        // Warm the agent cache (as an interactive pinentry would), then the non-interactive decode succeeds.
        let armored = MIMEEntity(data: RFC822Message(data: encrypted).bodyEntity).children[1].decodedBody
        let warmed = try runCLI(TestKeyring.gpgPath, ["--homedir", home.path, "--batch", "--no-tty", "--pinentry-mode",
                                                      "loopback", "--passphrase", "carol-secret", "--decrypt"], stdin: armored)
        XCTAssertEqual(warmed.exitCode, 0, warmed.stderr)
        let unlocked = try XCTUnwrap(PGPMIMEDecoder.decode(message: encrypted, gpg: runner, interactive: false))
        XCTAssertFalse(unlocked.needsPassphrase)
        XCTAssertNil(unlocked.error)
        XCTAssertTrue(MIMEEntity(data: RFC822Message(data: try XCTUnwrap(unlocked.message)).bodyEntity).text?
            .contains("Umlauts") ?? false)
    }
}
