import Foundation
import XCTest
@testable import SigilCore

final class PresentationTests: XCTestCase {
    let original = Data("original message".utf8)
    let decoded = Data("decoded message".utf8)
    let fpr = "0123456789ABCDEF0123456789ABCDEF01234567"

    func signer(_ status: SignatureStatus, validity: TrustLevel? = .fully, email: String? = "alice@example.org",
                userID: String? = "Alice <alice@example.org>") -> SignerInfo {
        SignerInfo(fingerprint: status == .noPublicKey ? nil : fpr, keyID: "89ABCDEF01234567", email: email,
                   userID: userID, validity: validity, status: status, created: Date(timeIntervalSince1970: 1_790_000_000))
    }

    func outcome(message: Data?, encrypted: Bool = false, partial: Bool = false, signers: [SignerInfo] = [],
                 error: String? = nil, needsPassphrase: Bool = false) -> DecodeOutcome {
        DecodeOutcome(message: message, classification: encrypted ? .pgpMimeEncrypted : .pgpMimeSigned,
                      encrypted: encrypted, signed: !signers.isEmpty, partial: partial, signers: signers,
                      error: error, needsPassphrase: needsPassphrase)
    }

    func present(_ o: DecodeOutcome) -> DecodePresentation { DecodePresentation.make(outcome: o, original: original) }

    func testGoodVerifiedSignature() throws {
        let p = present(outcome(message: decoded, signers: [signer(.good)]))
        XCTAssertEqual(p.rawData, decoded)
        XCTAssertFalse(p.isEncrypted)
        XCTAssertNil(p.signingError)
        XCTAssertNil(p.encryptionError)
        XCTAssertNil(p.banner)
        XCTAssertNil(p.context)
        XCTAssertFalse(p.blocksRemoteContent)
        XCTAssertEqual(p.signers.count, 1)
        XCTAssertEqual(p.signers[0].emailAddresses, ["alice@example.org"])
        XCTAssertEqual(p.signers[0].label, "Alice <alice@example.org> (verified key)")
        let context = try XCTUnwrap(SignerContext.decode(p.signers[0].context))
        XCTAssertEqual(context.fingerprint, fpr)
        XCTAssertEqual(context.validity, .fully)
        XCTAssertEqual(context.status, .good)
        XCTAssertFalse(context.partial)
    }

    func testGoodUnverifiedSignatureIsNotAnError() {
        for validity: TrustLevel? in [.undefined, .marginal, nil] {
            let p = present(outcome(message: decoded, signers: [signer(.good, validity: validity)]))
            XCTAssertNil(p.signingError)
            XCTAssertEqual(p.signers[0].label, "Alice <alice@example.org> (unverified key)")
        }
        let ultimate = present(outcome(message: decoded, signers: [signer(.good, validity: .ultimate)]))
        XCTAssertEqual(ultimate.signers[0].label, "Alice <alice@example.org> (verified key)")
    }

    func testDistrustedKeyIsAnError() {
        let p = present(outcome(message: decoded, signers: [signer(.good, validity: .never)]))
        XCTAssertTrue(p.signers.isEmpty, "a distrusted key must not show as signed")
        XCTAssertEqual(p.signingError, "The key of Alice <alice@example.org> is marked as not trusted in your keyring.")
    }

    func testFailingSignaturesGiveSigningErrors() throws {
        let cases: [(SignatureStatus, String, String)] = [
            (.bad, "INVALID signature – ", "is invalid: the message was changed after it was signed"),
            (.expiredSignature, "Expired signature – ", "has expired"),
            (.expiredKey, "Expired key – ", "with a key that has expired"),
            (.revokedKey, "Revoked key – ", "with a key that has been revoked"),
            (.noPublicKey, "Unknown key – key 0x89ABCDEF01234567", "unknown key (0x89ABCDEF01234567)"),
            (.error, "Signature NOT CHECKED – ", "could not be checked. gpg exploded"),
        ]
        for (status, label, error) in cases {
            let email: String? = status == .noPublicKey ? nil : "alice@example.org"
            let userID: String? = status == .noPublicKey ? nil : "Alice <alice@example.org>"
            let p = present(outcome(message: decoded, signers: [signer(status, email: email, userID: userID)],
                                    error: status == .error ? "gpg exploded" : nil))
            XCTAssertTrue(String(decoding: p.rawData, as: UTF8.self).hasSuffix("decoded message\r\n--"+"") || String(decoding: p.rawData, as: UTF8.self).contains("decoded message"), "\(status)")
            XCTAssertTrue(p.signers.isEmpty, "\(status): a failing signature must not show as signed")
            let shown = SignerPresentation(signer: signer(status, email: email, userID: userID), partial: false)
            XCTAssertTrue(shown.label.hasPrefix(label), "\(status): \(shown.label)")
            XCTAssertTrue(try XCTUnwrap(p.signingError).contains(error), "\(status): \(p.signingError ?? "nil")")
            XCTAssertNil(p.encryptionError)
        }
        let unknown = SignerPresentation(signer: signer(.noPublicKey, email: nil, userID: nil), partial: false)
        XCTAssertEqual(unknown.label, "Unknown key – key 0x89ABCDEF01234567")
        XCTAssertEqual(unknown.emailAddresses, [])
    }

    func testMixedSignersReportEveryProblem() {
        let p = present(outcome(message: decoded, signers: [signer(.good), signer(.bad, email: "bob@example.org", userID: "Bob <bob@example.org>")]))
        XCTAssertEqual(p.signers.map(\.emailAddresses), [["alice@example.org"]], "only the valid signer shows as signed")
        XCTAssertEqual(p.signingError, "The signature of Bob <bob@example.org> is invalid: the message was changed after it was signed.")
    }

    func testPartialSignatureIsNotFullySigned() throws {
        let p = present(outcome(message: decoded, partial: true, signers: [signer(.good)]))
        XCTAssertEqual(p.signingError, "Only part of this message is signed. Text outside the signed part may have been added by someone else.")
        XCTAssertTrue(p.signers.isEmpty, "a partial signature must not show as signed")
        let shown = SignerPresentation(signer: signer(.good), partial: true)
        XCTAssertEqual(shown.label, "Alice <alice@example.org> (verified key, only part of the message is signed)")
        XCTAssertEqual(p.banner, BannerPresentation(title: "Only part of this message is signed.", actionTitle: "Details", dismissable: false))
        XCTAssertTrue(try XCTUnwrap(SignerContext.decode(shown.context)).partial)
        // A real signature problem takes precedence over the partial note.
        let bad = present(outcome(message: decoded, partial: true, signers: [signer(.bad)]))
        XCTAssertTrue(bad.signingError?.contains("invalid") ?? false)
    }

    func testDecryptedMessageBlocksRemoteContent() {
        let p = present(outcome(message: decoded, encrypted: true, signers: [signer(.good)]))
        XCTAssertEqual(p.rawData, decoded)
        XCTAssertTrue(p.isEncrypted)
        XCTAssertTrue(p.blocksRemoteContent)
        XCTAssertEqual(p.remoteContentBlockingReason, DecodePresentation.remoteContentReason)
        XCTAssertNil(p.encryptionError)
        XCTAssertNil(p.banner)
        let unsigned = present(outcome(message: decoded, encrypted: true))
        XCTAssertTrue(unsigned.signers.isEmpty)
        XCTAssertNil(unsigned.signingError)
    }

    func testPartiallyEncryptedIsNotShownAsEncrypted() throws {
        let p = present(outcome(message: decoded, encrypted: true, partial: true))
        XCTAssertFalse(p.isEncrypted)
        XCTAssertTrue(p.blocksRemoteContent)
        XCTAssertEqual(p.banner, BannerPresentation(title: "Only part of this message is encrypted.", actionTitle: "Details", dismissable: true))
        XCTAssertEqual(try XCTUnwrap(MessageContext.decode(try XCTUnwrap(p.context))).action, .partialInfo)
    }

    func testDecryptionFailureHasNoPlaintext() throws {
        let p = present(outcome(message: nil, encrypted: true, error: "Decryption failed: bad data"))
        XCTAssertTrue(p.isEncrypted)
        XCTAssertEqual(p.encryptionError, "This message could not be decrypted. Decryption failed: bad data")
        XCTAssertNil(p.signingError)
        XCTAssertTrue(p.signers.isEmpty)
        XCTAssertEqual(p.banner, BannerPresentation(
            title: "Sigil could not decrypt this message: Decryption failed: bad data", actionTitle: "Details", dismissable: false))
        XCTAssertEqual(try? XCTUnwrap(MessageContext.decode(try XCTUnwrap(p.context))).action, .info)
    }

    func testDecryptionFailureReplacesCiphertext() throws {
        let ciphertext = "-----BEGIN PGP MESSAGE-----\nSECRETCIPHERTEXT\n-----END PGP MESSAGE-----\n"
        let mail = Data(("From: a@example.org\nTo: b@example.org\nSubject: Hi\nDate: Mon, 1 Jan 2026 10:00:00 +0000\n"
            + "Content-Type: text/plain\n\n" + ciphertext).utf8)
        let p = DecodePresentation.make(outcome: outcome(message: nil, encrypted: true, error: "bad data"), original: mail)
        let text = String(decoding: p.rawData, as: UTF8.self)
        XCTAssertFalse(text.contains("-----BEGIN PGP"))
        XCTAssertFalse(text.contains("SECRETCIPHERTEXT"))
        XCTAssertTrue(text.contains("Content-Type: multipart/alternative"))
        XCTAssertFalse(text.contains("multipart/mixed"))
        XCTAssertTrue(text.contains("\u{26D4} Sigil: Sigil could not decrypt this message."))
        XCTAssertTrue(text.contains("#c62828"))
        XCTAssertTrue(text.contains("bad data"))
        let parsed = RFC822Message(data: p.rawData)
        XCTAssertEqual(parsed.header("From"), "a@example.org")
        XCTAssertEqual(parsed.header("To"), "b@example.org")
        XCTAssertEqual(parsed.header("Subject"), "Hi")
        XCTAssertNotNil(parsed.header("Date"))
        XCTAssertTrue(p.isEncrypted)
        XCTAssertNotNil(p.encryptionError)
    }

    func testBannerPerProblemKind() {
        let cases: [(SignatureStatus, TrustLevel?, String, Bool)] = [
            (.bad, .fully, "Invalid signature: this message was changed after it was signed.", false),
            (.revokedKey, .fully, "Signature from a revoked key.", false),
            (.expiredKey, .fully, "Signature from an expired key.", true),
            (.good, .never, "Signed with a key you marked as not trusted.", true),
            (.noPublicKey, nil, "Signed with an unknown key. The signature could not be checked.", true),
        ]
        for (status, validity, title, dismissable) in cases {
            let p = present(outcome(message: decoded, signers: [signer(status, validity: validity)]))
            XCTAssertEqual(p.banner, BannerPresentation(title: title, actionTitle: "Details", dismissable: dismissable), "\(status)")
        }
        XCTAssertNil(present(outcome(message: decoded, signers: [signer(.good)])).banner)
    }

    func testBannerSeverityOrder() {
        let order: [SignerInfo] = [signer(.bad), signer(.revokedKey), signer(.expiredKey), signer(.good, validity: .never),
                                   signer(.noPublicKey)]
        let titles = ["Invalid signature", "Signature from a revoked", "Signature from an expired", "Signed with a key you marked",
                      "Signed with an unknown"]
        for start in order.indices {
            let p = present(outcome(message: decoded, signers: Array(order[start...].reversed())))
            XCTAssertTrue(p.banner?.title.hasPrefix(titles[start]) ?? false, "\(start): \(p.banner?.title ?? "nil")")
        }
        let partialUnknown = present(outcome(message: decoded, partial: true, signers: [signer(.noPublicKey)]))
        XCTAssertTrue(partialUnknown.banner?.title.hasPrefix("Signed with an unknown") ?? false)
        // A signature problem wins over the partial-encryption banner.
        let both = present(outcome(message: decoded, encrypted: true, partial: true, signers: [signer(.bad)]))
        XCTAssertTrue(both.banner?.title.hasPrefix("Invalid signature") ?? false)
    }

    func testInfoContextRoundTrip() throws {
        let p = present(outcome(message: decoded, signers: [signer(.bad)]))
        let context = try XCTUnwrap(MessageContext.decode(try XCTUnwrap(p.context)))
        XCTAssertEqual(context.action, .info)
        XCTAssertEqual(context.heading, p.banner?.title)
        XCTAssertEqual(context.detail, p.signingError)
        XCTAssertNil(try XCTUnwrap(p.context).range(of: decoded))
    }

    func testOldContextWithoutHeadingDecodes() throws {
        let old = Data(#"{"action":"decrypt","messageHash":"abc"}"#.utf8)
        let context = try XCTUnwrap(MessageContext.decode(old))
        XCTAssertEqual(context, MessageContext(action: .decrypt, messageHash: "abc"))
        XCTAssertNil(context.heading)
        XCTAssertNil(context.detail)
    }

    func testSignerLabelMarkers() {
        XCTAssertEqual(SignerPresentation(signer: signer(.bad), partial: false).label,
                       "INVALID signature – Alice <alice@example.org>")
        XCTAssertEqual(SignerPresentation(signer: signer(.expiredKey), partial: false).label,
                       "Expired key – Alice <alice@example.org>")
        XCTAssertEqual(SignerPresentation(signer: signer(.revokedKey), partial: false).label,
                       "Revoked key – Alice <alice@example.org>")
        XCTAssertEqual(SignerPresentation(signer: signer(.good, validity: .never), partial: false).label,
                       "NOT TRUSTED key – Alice <alice@example.org>")
    }

    func testFatalErrorWithoutEncryptionIsASigningError() {
        let p = present(outcome(message: nil, error: "Malformed message: x"))
        XCTAssertTrue(String(decoding: p.rawData, as: UTF8.self).contains("original message"))
        XCTAssertEqual(p.signingError, "This message could not be checked. Malformed message: x")
        XCTAssertNil(p.encryptionError)
        XCTAssertEqual(p.banner?.title, "Sigil could not check this message: Malformed message: x")
    }

    func testNeedsPassphraseShowsDecryptBanner() throws {
        let p = present(outcome(message: nil, encrypted: true, error: "A passphrase is required.", needsPassphrase: true))
        XCTAssertEqual(p.rawData, original)
        XCTAssertTrue(p.isEncrypted)
        XCTAssertNil(p.encryptionError)
        XCTAssertNil(p.signingError)
        XCTAssertEqual(p.banner, BannerPresentation(title: "This message is encrypted.", actionTitle: "Decrypt", dismissable: false))
        let context = try XCTUnwrap(MessageContext.decode(try XCTUnwrap(p.context)))
        XCTAssertEqual(context, MessageContext(action: .decrypt, messageHash: MessageContext.hash(of: original)))
        XCTAssertEqual(context.messageHash.count, 64)
        // The context only identifies the message; it does not contain it.
        XCTAssertNil(try XCTUnwrap(p.context).range(of: original))
    }

    func testHelperFailureShowsRetryBanner() throws {
        let p = DecodePresentation.helperFailure(original: original, title: "Sigil helper not reachable.")
        XCTAssertEqual(p.rawData, original)
        XCTAssertEqual(p.banner, BannerPresentation(title: "Sigil helper not reachable.", actionTitle: "Retry", dismissable: true))
        XCTAssertEqual(try XCTUnwrap(MessageContext.decode(try XCTUnwrap(p.context))).action, .retry)
        XCTAssertTrue(p.signers.isEmpty)
        XCTAssertNil(p.signingError)
        XCTAssertNil(p.encryptionError)
    }

    func testSignerDetails() throws {
        let fixedDate: (Date) -> String = { _ in "DATE" }
        let verified = SignerDetails(context: SignerContext(signer: signer(.good), partial: false), dateFormatter: fixedDate)
        XCTAssertEqual(verified.title, "Alice <alice@example.org>")
        XCTAssertEqual(verified.rows.map(\.label), ["Email", "Fingerprint", "Key", "Signature", "Signed"])
        XCTAssertEqual(verified.rows[1].value, "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567")
        XCTAssertEqual(verified.rows[2].value, "Verified")
        XCTAssertEqual(verified.rows[3].value, "Good signature")
        XCTAssertEqual(verified.rows[4].value, "DATE")
        XCTAssertNil(verified.hint)

        let unverified = SignerDetails(context: SignerContext(signer: signer(.good, validity: .undefined), partial: true))
        XCTAssertEqual(unverified.rows[2].value, "Not verified")
        XCTAssertTrue(unverified.rows[3].value.contains("only part"))
        XCTAssertTrue(try XCTUnwrap(unverified.hint).contains("gpg --lsign-key \(fpr)"))

        let unknown = SignerDetails(context: SignerContext(signer: signer(.noPublicKey, validity: nil, email: nil, userID: nil), partial: false))
        XCTAssertEqual(unknown.rows[1].value, "Key ID 0x89ABCDEF01234567")
        XCTAssertTrue(try XCTUnwrap(unknown.hint).contains("--recv-keys"))
    }

    func testFingerprintGrouping() {
        XCTAssertEqual(Fingerprint.grouped("abcdef0123"), "ABCD EF01 23")
        XCTAssertEqual(Fingerprint.grouped(""), "")
    }

    func testMessageByteCacheEvictsLeastRecentlyUsed() {
        let cache = MessageByteCache(capacity: 2)
        cache.insert(Data([1]), hash: "a")
        cache.insert(Data([2]), hash: "b")
        XCTAssertEqual(cache.data(forHash: "a"), Data([1]))  // a is now most recent
        cache.insert(Data([3]), hash: "c")
        XCTAssertNil(cache.data(forHash: "b"))
        XCTAssertEqual(cache.data(forHash: "a"), Data([1]))
        XCTAssertEqual(cache.data(forHash: "c"), Data([3]))
        cache.remove(hash: "a")
        XCTAssertNil(cache.data(forHash: "a"))
    }

    // MARK: Warning box

    let body = "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nHello \u{00E4}\r\nworld"
    var mail: Data { Data(("From: a@example.org\r\nSubject: Hi\r\n" + body).utf8) }

    /// Returns (boundary, box entity text, second part bytes) of a `multipart/mixed` message.
    func splitBox(_ data: Data) throws -> (String, String, Data) {
        let parsed = RFC822Message(data: data)
        let ct = try XCTUnwrap(MIMEEntity(data: data).contentType)
        XCTAssertEqual(ct.type, "multipart")
        XCTAssertEqual(ct.subtype, "mixed")
        let boundary = try XCTUnwrap(ct.parameters["boundary"])
        let text = String(decoding: parsed.bodyEntity, as: UTF8.self)
        let marker = "--\(boundary)\r\n"
        let start1 = try XCTUnwrap(text.range(of: marker))
        let start2 = try XCTUnwrap(text.range(of: marker, range: start1.upperBound..<text.endIndex))
        let end = try XCTUnwrap(text.range(of: "\r\n--\(boundary)--"))
        let first = String(text[start1.upperBound..<text.index(start2.lowerBound, offsetBy: -2)])
        let secondBytes = Data(text[start2.upperBound..<end.lowerBound].utf8)
        return (boundary, first, secondBytes)
    }

    func testRedBoxForBadSignature() throws {
        let label = "Ev&\"<b>\" <eve@example.org>"
        let s = signer(.bad, email: "eve@example.org", userID: label)
        let p = DecodePresentation.make(outcome: outcome(message: mail, signers: [s]), original: original)
        let (_, box, second) = try splitBox(p.rawData)
        XCTAssertEqual(RFC822Message(data: p.rawData).header("From"), "a@example.org")
        XCTAssertTrue(box.contains("Content-Type: multipart/alternative"))
        XCTAssertTrue(box.contains("Content-Type: text/plain; charset=utf-8"))
        XCTAssertTrue(box.contains("Content-Type: text/html; charset=utf-8"))
        XCTAssertTrue(box.contains("\u{26D4} Sigil: Invalid signature: this message was changed after it was signed."))
        XCTAssertTrue(box.contains("Fingerprint: 0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"))
        for c in ["#c62828", "#fdecea", "#7f1d1d", "4px solid", "padding: 10px 14px", "border-radius: 6px", "margin-bottom: 12px"] {
            XCTAssertTrue(box.contains(c), c)
        }
        XCTAssertFalse(box.contains("<script"))
        XCTAssertTrue(box.contains("&lt;b&gt;"), box)
        XCTAssertTrue(box.contains("&amp;"))
        XCTAssertTrue(box.contains("&quot;"))
        XCTAssertEqual(second, RFC822Message(data: mail).bodyEntity)
    }

    func testYellowBoxForUnknownKeyAndExtraProblems() throws {
        let p = DecodePresentation.make(
            outcome: outcome(message: mail, signers: [signer(.noPublicKey), signer(.revokedKey)]), original: original)
        let (_, box, second) = try splitBox(p.rawData)
        XCTAssertTrue(box.contains("\u{26A0}\u{FE0F} Sigil: Signature from a revoked key."))
        XCTAssertTrue(box.contains("unknown key"), "extra problems are listed")
        XCTAssertFalse(box.contains("\u{26D4}"))
        for c in ["#f9a825", "#fff8e1", "#6d4c00"] { XCTAssertTrue(box.contains(c), c) }
        XCTAssertEqual(second, RFC822Message(data: mail).bodyEntity)
    }

    func testDecryptionFailureBoxHasNoCiphertext() throws {
        let mailIn = Data("From: a@example.org\nContent-Type: text/plain\n\n-----BEGIN PGP MESSAGE-----\nX\n-----END PGP MESSAGE-----\n".utf8)
        let p = DecodePresentation.make(outcome: outcome(message: nil, encrypted: true, error: "bad data"), original: mailIn)
        XCTAssertFalse(String(decoding: p.rawData, as: UTF8.self).contains("BEGIN PGP"))
        XCTAssertNotNil(p.banner)
    }

    func testGoodSignatureIsUnchanged() {
        let p = present(outcome(message: decoded, signers: [signer(.good, validity: .undefined)]))
        XCTAssertEqual(p.rawData, decoded)
    }
}
