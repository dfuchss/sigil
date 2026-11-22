import Foundation
import XCTest
@testable import SigilCore

final class IncompleteMessageTests: XCTestCase {
    static let armor = "-----BEGIN PGP MESSAGE-----\r\n\r\n" + String(repeating: "hQEMA0123456789abcdefABCDEF==\r\n", count: 20)
        + "-----END PGP MESSAGE-----\r\n"
    static let signature = "-----BEGIN PGP SIGNATURE-----\r\n\r\n" + String(repeating: "iQEzBAABCAAdFiEE0123456789abcd\r\n", count: 8)
        + "-----END PGP SIGNATURE-----\r\n"

    static func headers(_ contentType: String) -> String {
        "From: Alice <alice@example.org>\r\nTo: Bob <bob@example.org>\r\nSubject: Test\r\nMIME-Version: 1.0\r\nContent-Type: \(contentType)\r\n\r\n"
    }

    static let encrypted = Data((headers("multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"E\"")
        + "--E\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--E\r\n"
        + "Content-Type: application/octet-stream\r\n\r\n" + armor + "--E--\r\n").utf8)

    static let signedBody = "Content-Type: multipart/alternative; boundary=\"A\"\r\n\r\n--A\r\nContent-Type: text/plain\r\n\r\nReadable text\r\n--A\r\n"
        + "Content-Type: text/html\r\n\r\n<p>Readable text</p>\r\n--A--\r\n"
    static let signed = Data((headers("multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"S\"")
        + "--S\r\n" + signedBody + "--S\r\nContent-Type: application/pgp-signature\r\n\r\n" + signature + "--S--\r\n").utf8)

    static let inlineEncrypted = sampleMessage(body: armor, cte: "7bit")
    static let inlineSigned = sampleMessage(body: "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nHello\r\n" + signature, cte: "7bit")

    static var all: [(String, Data)] {
        [("encrypted", encrypted), ("signed", signed), ("inlineEncrypted", inlineEncrypted), ("inlineSigned", inlineSigned)]
    }

    func headerLength(_ data: Data) -> Int {
        let b = [UInt8](data)
        return MIMEHeaders.parse(b, 0, b.count).bodyStart
    }

    func testFullMessagesAreComplete() {
        for (name, data) in Self.all {
            XCTAssertTrue(PGPDetector.isComplete(messageData: data), name)
            XCTAssertTrue(PGPDetector.isComplete(messageData: LineEndings.toLF(data)), name + " LF")
        }
    }

    func testTruncatedMessagesAreIncomplete() {
        for (name, full) in Self.all {
            for variant in [full, LineEndings.toLF(full)] {
                let n = variant.count
                for cut in [n / 4, n / 3, n / 2, n * 2 / 3, n * 3 / 4, n - 10, n - 3] {
                    let truncated = variant.prefix(cut)
                    // Cutting inside the headers leaves nothing to judge.
                    guard cut > headerLength(variant) + 10 else { continue }
                    XCTAssertFalse(PGPDetector.isComplete(messageData: Data(truncated)), "\(name) cut at \(cut)")
                }
            }
        }
    }

    func testNestedEncryptedIsIncompleteWhenTruncated() throws {
        // multipart/mixed wrapping a multipart/encrypted part
        let inner = String(decoding: Self.encrypted, as: UTF8.self)
        let part = inner.components(separatedBy: "MIME-Version: 1.0\r\n")[1]
        let full = Data((Self.headers("multipart/mixed; boundary=\"M\"") + "--M\r\n" + part + "\r\n--M--\r\n").utf8)
        XCTAssertEqual(PGPDetector.classify(messageData: full), .pgpMimeEncrypted)
        XCTAssertTrue(PGPDetector.isComplete(messageData: full))
        XCTAssertFalse(PGPDetector.isComplete(messageData: full.prefix(full.count - 8)))
        XCTAssertFalse(PGPDetector.isComplete(messageData: full.prefix(full.count / 2)))
    }

    func testNonPGPMessagesAreComplete() throws {
        XCTAssertTrue(PGPDetector.isComplete(messageData: sampleMessage()))
        XCTAssertTrue(PGPDetector.isComplete(messageData: try Fixtures.data("plain")))
        XCTAssertTrue(PGPDetector.isComplete(messageData: try Fixtures.data("nested-multipart")))
        XCTAssertTrue(PGPDetector.isComplete(messageData: try Fixtures.data("qp-8bit")))
    }

    func testEncryptedPreview() {
        for full in [Self.encrypted, Self.inlineEncrypted] {
            let cls = PGPDetector.classify(messageData: full)
            let truncated = Data(full.prefix(full.count / 2))
            let p = DecodePresentation.preview(original: truncated, classification: cls == .none ? .inline : cls)
            let text = p.rawData.string
            XCTAssertFalse(text.contains("BEGIN PGP"))
            XCTAssertFalse(text.contains("hQEMA"))
            XCTAssertTrue(text.contains("🔒 Encrypted message"))
            XCTAssertTrue(text.contains("Subject: Test"))
            XCTAssertTrue(text.contains("text/plain; charset=utf-8"))
            XCTAssertTrue(p.isEncrypted)
            XCTAssertNil(p.encryptionError)
            XCTAssertNil(p.signingError)
            XCTAssertNil(p.banner)
            XCTAssertNil(p.context)
            XCTAssertTrue(p.signers.isEmpty)
            XCTAssertTrue(p.blocksRemoteContent)
        }
    }

    func testSignedPreviewKeepsCompleteFirstPart() {
        // Cut inside the signature part: first child is complete.
        let cut = Self.signed.range(of: Data("application/pgp-signature\r\n\r\n".utf8))!.upperBound + 40
        let p = DecodePresentation.preview(original: Data(Self.signed.prefix(cut)), classification: .pgpMimeSigned)
        let text = p.rawData.string
        XCTAssertTrue(text.contains("Readable text"))
        XCTAssertTrue(text.contains("Subject: Test"))
        XCTAssertFalse(text.contains("BEGIN PGP SIGNATURE"))
        XCTAssertFalse(text.contains("--S"))
        let entity = MIMEEntity(data: RFC822Message(data: p.rawData).bodyEntity)
        XCTAssertEqual(entity.contentType.mimeType, "multipart/alternative")
        XCTAssertTrue(entity.isTerminated)
        XCTAssertFalse(p.isEncrypted)
        XCTAssertTrue(p.signers.isEmpty)
        XCTAssertNil(p.signingError)
        XCTAssertNil(p.banner)
        XCTAssertFalse(p.blocksRemoteContent)
    }

    func testSignedPreviewWithTruncatedFirstPartIsUnchanged() {
        let truncated = Data(Self.signed.prefix(Self.signed.count / 4))
        let p = DecodePresentation.preview(original: truncated, classification: .pgpMimeSigned)
        XCTAssertEqual(p.rawData, truncated)
        XCTAssertTrue(p.signers.isEmpty)
        XCTAssertNil(p.banner)
        XCTAssertNil(p.signingError)
    }

    func testInlineSignedPreviewIsUnchanged() {
        let truncated = Data(Self.inlineSigned.prefix(Self.inlineSigned.count - 60))
        let p = DecodePresentation.preview(original: truncated, classification: .inline)
        XCTAssertEqual(p.rawData, truncated)
        XCTAssertTrue(p.signers.isEmpty)
        XCTAssertFalse(p.isEncrypted)
        XCTAssertNil(p.banner)
    }
}
