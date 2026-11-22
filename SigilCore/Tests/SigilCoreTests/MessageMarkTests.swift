import Foundation
import XCTest
@testable import SigilCore

final class MessageMarkTests: XCTestCase {
    func signer(_ status: SignatureStatus, validity: TrustLevel? = .fully) -> SignerInfo {
        SignerInfo(fingerprint: nil, keyID: "89ABCDEF01234567", email: "alice@example.org",
                   userID: "Alice <alice@example.org>", validity: validity, status: status)
    }

    func outcome(message: Data? = Data("m".utf8), encrypted: Bool = false, signed: Bool? = nil, partial: Bool = false,
                 signers: [SignerInfo] = [], error: String? = nil, needsPassphrase: Bool = false,
                 classification: MessageClassification = .pgpMimeSigned) -> DecodeOutcome {
        DecodeOutcome(message: message, classification: classification, encrypted: encrypted,
                      signed: signed ?? !signers.isEmpty, partial: partial, signers: signers, error: error,
                      needsPassphrase: needsPassphrase)
    }

    func testRed() {
        XCTAssertEqual(MessageMark.of(outcome(signers: [signer(.bad)])), .red)
        let tampered = outcome(message: nil, encrypted: true, error: GPGError.integrityCheckFailed.errorDescription)
        XCTAssertEqual(MessageMark.of(tampered), .red)
    }

    func testYellow() {
        for status: SignatureStatus in [.revokedKey, .expiredSignature, .expiredKey, .noPublicKey, .error] {
            XCTAssertEqual(MessageMark.of(outcome(signers: [signer(status)])), .yellow, "\(status)")
        }
        XCTAssertEqual(MessageMark.of(outcome(signers: [signer(.good, validity: .never)])), .yellow)
        XCTAssertEqual(MessageMark.of(outcome(partial: true, signers: [signer(.good)])), .yellow)
    }

    func testNone() {
        for validity: TrustLevel? in [.fully, .ultimate, .marginal, .undefined, nil] {
            XCTAssertEqual(MessageMark.of(outcome(signers: [signer(.good, validity: validity)])), .none)
        }
        XCTAssertEqual(MessageMark.of(outcome(message: nil, encrypted: true, error: "A passphrase is required.",
                                              needsPassphrase: true)), .none)
        XCTAssertEqual(MessageMark.of(outcome(message: nil, encrypted: true,
                                              error: GPGError.noSecretKey(["ABC"]).errorDescription)), .none)
        XCTAssertEqual(MessageMark.of(outcome(encrypted: true, classification: .pgpMimeEncrypted)), .none)
        XCTAssertEqual(MessageMark.of(outcome(encrypted: true, partial: true, classification: .inline)), .none)
        XCTAssertEqual(MessageMark.of(outcome(classification: .none)), .none)
    }

    func testWorstWins() {
        XCTAssertEqual(MessageMark.of(outcome(signers: [signer(.good), signer(.noPublicKey), signer(.bad)])), .red)
        XCTAssertEqual(MessageMark.of(outcome(partial: true, signers: [signer(.bad)])), .red)
        XCTAssertEqual(MessageMark.of(outcome(signers: [signer(.good), signer(.expiredKey)])), .yellow)
    }
}
