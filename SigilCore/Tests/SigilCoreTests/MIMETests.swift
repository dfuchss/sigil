import Foundation
import XCTest
@testable import SigilCore

final class MIMETests: XCTestCase {
    func testPlainMessage() throws {
        let data = try Fixtures.data("plain")
        let e = MIMEEntity(data: data)
        XCTAssertEqual(e.contentType.mimeType, "text/plain")
        XCTAssertEqual(e.headers["subject"], "Plain message")
        XCTAssertTrue(e.text?.contains("without any OpenPGP content") ?? false)
        XCTAssertEqual(PGPDetector.classify(messageData: data), .none)
    }

    func testHeaderUnfolding() {
        let raw = Data("Subject: a\r\n  folded\r\n\tline\r\nX: y\r\n\r\nbody".utf8)
        let e = MIMEEntity(data: raw)
        XCTAssertEqual(e.headers["Subject"], "a  folded\tline")
        XCTAssertEqual(e.headers.fields[0].raw, Data("Subject: a\r\n  folded\r\n\tline\r\n".utf8))
        XCTAssertEqual(e.rawBody, Data("body".utf8))
    }

    func testContentTypeParameters() {
        let ct = ContentType(parsing: "Multipart/Signed; micalg=pgp-sha256; protocol=\"application/pgp-signature\"; boundary=\"a;b \\\"c\\\"\" (comment)")
        XCTAssertEqual(ct.mimeType, "multipart/signed")
        XCTAssertEqual(ct.parameter("micalg"), "pgp-sha256")
        XCTAssertEqual(ct.parameter("protocol"), "application/pgp-signature")
        XCTAssertEqual(ct.boundary, "a;b \"c\"")

        let cd = ParameterizedHeader(parsing: "attachment; filename*=iso-8859-1'de'K%F6ln.txt")
        XCTAssertEqual(cd.parameters["filename"], "Köln.txt")
        let cont = ParameterizedHeader(parsing: "attachment; name*0=\"long \"; name*1=\"name.txt\"")
        XCTAssertEqual(cont.parameters["name"], "long name.txt")
        XCTAssertEqual(ContentType(parsing: nil), .defaultText)
    }

    func testNestedMultipart() throws {
        let data = try Fixtures.data("nested-multipart")
        let e = MIMEEntity(data: data)
        XCTAssertEqual(e.contentType.mimeType, "multipart/mixed")
        XCTAssertEqual(e.children.count, 2)
        XCTAssertTrue(e.isTerminated)
        let alt = e.children[0]
        XCTAssertEqual(alt.contentType.mimeType, "multipart/alternative")
        XCTAssertEqual(alt.children.count, 2)
        XCTAssertEqual(alt.children[0].text, "Grüße aus Köln")
        XCTAssertEqual(alt.children[1].text, "<p>Grüße aus Köln</p>")
        let att = e.children[1]
        XCTAssertEqual(att.filename, "résumé.bin")
        XCTAssertTrue(att.isAttachment)
        XCTAssertEqual(att.decodedBody, Data(0..<16))
        XCTAssertEqual(e.leaves.count, 3)
        // Preamble/epilogue are not part of any child.
        XCTAssertFalse(e.children.contains { $0.rawData.string.contains("preamble") || $0.rawData.string.contains("epilogue") })
        XCTAssertEqual(PGPDetector.classify(messageData: data), .none)
    }

    func testSignedRangeIsByteExact() throws {
        let data = try Fixtures.data("signed-static")
        let e = MIMEEntity(data: data)
        XCTAssertTrue(e.isPGPMIMESigned)
        XCTAssertEqual(e.children.count, 2)
        let expected = "Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\nSigned text.\r\n"
        XCTAssertEqual(e.children[0].rawData, Data(expected.utf8))
        // The recorded range points into the original bytes.
        XCTAssertEqual(data.subdata(in: e.children[0].range), Data(expected.utf8))
        XCTAssertEqual(PGPDetector.classify(messageData: data), .pgpMimeSigned)

        // Rebuild and re-parse: the first part must come back byte-identical.
        let rebuilt = MIMEBuilder.multipartSigned(signedEntity: e.children[0].rawData,
                                                  signature: e.children[1].decodedBody, micalg: "pgp-sha256")
        let re = MIMEEntity(data: rebuilt)
        XCTAssertTrue(re.isPGPMIMESigned)
        XCTAssertEqual(re.children[0].rawData, Data(expected.utf8))
        XCTAssertEqual(re.children[1].decodedBody, e.children[1].decodedBody)
        XCTAssertFalse(rebuilt.string.replacingOccurrences(of: "\r\n", with: "").contains("\n"), "CRLF only")
    }

    func testSignedRangeWithoutTrailingNewline() {
        let raw = Data("Content-Type: multipart/signed; boundary=x; protocol=\"application/pgp-signature\"\r\n\r\n--x\r\nA: b\r\n\r\nno newline\r\n--x\r\n\r\nsig\r\n--x--".utf8)
        let e = MIMEEntity(data: raw)
        XCTAssertEqual(e.children.map(\.rawData.string), ["A: b\r\n\r\nno newline", "\r\nsig"])
        // A line that merely starts with the boundary is not a delimiter.
        let raw2 = Data("Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\n--xy\r\n--x--\r\n".utf8)
        XCTAssertEqual(MIMEEntity(data: raw2).children.map(\.rawData.string), ["\r\n--xy"])
    }

    func testSplitAndRecombine() throws {
        let data = try Fixtures.data("plain")
        let msg = RFC822Message(data: data)
        XCTAssertEqual(msg.outerHeaders.map(\.name), ["From", "To", "Subject", "Date", "Message-ID", "MIME-Version"])
        XCTAssertTrue(msg.bodyEntity.string.hasPrefix("Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHello Bob"))
        XCTAssertEqual(msg.serialized(), data)
    }

    func testTransferEncodings() {
        let qp = Data("Gr=C3=BC=C3=9Fe=\r\n zusammen   \r\nx=3D1".utf8)
        XCTAssertEqual(QuotedPrintable.decode(qp).string, "Grüße zusammen\r\nx=1")
        let text = Data("From me\nline with trailing space \n\(String(repeating: "ä", count: 60))\n.\n".utf8)
        let enc = QuotedPrintable.encodeText(text)
        for line in enc.string.components(separatedBy: "\r\n") {
            XCTAssertLessThanOrEqual(line.count, 76)
            XCTAssertFalse(line.hasPrefix("From "))
            XCTAssertFalse(line.hasSuffix(" "))
        }
        XCTAssertEqual(QuotedPrintable.decode(enc), LineEndings.toCRLF(text))
        let bin = Data((0..<200).map { UInt8($0) })
        XCTAssertEqual(Base64.decode(Base64.encode(bin)), bin)
        XCTAssertTrue(Base64.encode(bin).string.components(separatedBy: "\r\n").allSatisfy { $0.count <= 76 })
    }

    func testCanonicalizer8bitBody() throws {
        let data = try Fixtures.data("qp-8bit")
        let msg = RFC822Message(data: data)
        let canon = Canonicalizer.canonicalize(entity: msg.bodyEntity)
        XCTAssertTrue(Bytes.isSevenBitClean(canon))
        let s = canon.string
        XCTAssertFalse(s.replacingOccurrences(of: "\r\n", with: "").contains("\n"), "only CRLF line endings")
        for line in s.components(separatedBy: "\r\n") {
            XCTAssertLessThanOrEqual(line.count, 76)
            XCTAssertFalse(line.hasPrefix("From "))
            XCTAssertFalse(line.hasSuffix(" ") || line.hasSuffix("\t"))
        }
        let e = MIMEEntity(data: canon)
        XCTAssertEqual(e.transferEncoding, .quotedPrintable)
        XCTAssertEqual(e.headers.values("Content-Transfer-Encoding").count, 1)
        let original = MIMEEntity(data: msg.bodyEntity).text!
        XCTAssertEqual(e.text, original.replacingOccurrences(of: "\n", with: "\r\n"))
        // Idempotent.
        XCTAssertEqual(Canonicalizer.canonicalize(entity: canon), canon)
    }

    func testCanonicalizerMultipartAndBinary() throws {
        let data = try Fixtures.data("nested-multipart")
        let canon = Canonicalizer.canonicalize(entity: RFC822Message(data: data).bodyEntity)
        XCTAssertTrue(Bytes.isSevenBitClean(canon))
        let e = MIMEEntity(data: canon)
        XCTAssertEqual(e.children.count, 2)
        XCTAssertEqual(e.children[0].children[1].text, "<p>Grüße aus Köln</p>")
        XCTAssertEqual(e.children[1].decodedBody, Data(0..<16))

        let binary = Data("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n".utf8) + Data([0, 0xFF, 0x0A, 0x41])
        let cb = MIMEEntity(data: Canonicalizer.canonicalize(entity: binary))
        XCTAssertEqual(cb.transferEncoding, .base64)
        XCTAssertEqual(cb.decodedBody, Data([0, 0xFF, 0x0A, 0x41]))
    }

    func testBuilderEncrypted() {
        let built = MIMEBuilder.multipartEncrypted(armoredCiphertext: Data("-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n".utf8))
        let e = MIMEEntity(data: built)
        XCTAssertTrue(e.isPGPMIMEEncrypted)
        XCTAssertEqual(e.children.count, 2)
        XCTAssertEqual(e.children[0].contentType.mimeType, "application/pgp-encrypted")
        XCTAssertEqual(e.children[0].decodedBody.string, "Version: 1\r\n")
        XCTAssertEqual(e.children[1].contentType.mimeType, "application/octet-stream")
        XCTAssertEqual(e.children[1].filename, "encrypted.asc")
        XCTAssertEqual(e.children[1].decodedBody.string, "-----BEGIN PGP MESSAGE-----\r\n\r\nabc\r\n-----END PGP MESSAGE-----\r\n")
        XCTAssertNotEqual(MIMEBuilder.randomBoundary(), MIMEBuilder.randomBoundary())
    }
}

final class PGPParsingTests: XCTestCase {
    func testArmorDetection() {
        let text = "Hi\n> -----BEGIN PGP MESSAGE-----\n-----BEGIN PGP MESSAGE-----\n\nhQ==\n-----END PGP MESSAGE-----\nmid\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhello\n-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\nbye"
        let blocks = Armor.blocks(in: text)
        XCTAssertEqual(blocks.map(\.kind), [.message, .signedMessage])
        let u = Array(text.utf8)
        XCTAssertEqual(String(decoding: u[blocks[0].range], as: UTF8.self), "-----BEGIN PGP MESSAGE-----\n\nhQ==\n-----END PGP MESSAGE-----")
        XCTAssertTrue(String(decoding: u[blocks[1].range], as: UTF8.self).hasSuffix("-----END PGP SIGNATURE-----"))
        XCTAssertTrue(Armor.blocks(in: "-----BEGIN PGP MESSAGE-----\nunterminated").isEmpty)

        let inline = sampleMessage(body: "-----BEGIN PGP MESSAGE-----\r\n\r\nhQ==\r\n-----END PGP MESSAGE-----\r\n", cte: "7bit")
        XCTAssertEqual(PGPDetector.classify(messageData: inline), .inline)
        let b64 = sampleMessage(body: Base64.encode(Data("-----BEGIN PGP MESSAGE-----\n\nhQ==\n-----END PGP MESSAGE-----\n".utf8)).string, cte: "base64")
        XCTAssertEqual(PGPDetector.classify(messageData: b64), .inline)
    }

    func testStatusParser() {
        let out = """
        gpg: some human text
        [GNUPG:] NEWSIG alice@example.org
        [GNUPG:] GOODSIG 1234567890ABCDEF Alice <alice@example.org>
        [GNUPG:] VALIDSIG AAAA 2026-11-21 1795000000 0 4 0 22 8 00 BBBB
        [GNUPG:] TRUST_ULTIMATE 0 pgp
        [GNUPG:] NEWSIG
        [GNUPG:] ERRSIG FEDCBA0987654321 22 8 00 1795000000 9 CCCC
        [GNUPG:] NO_PUBKEY FEDCBA0987654321
        [GNUPG:] NEWSIG
        [GNUPG:] BADSIG 1111 Bob %25 <bob@example.org>
        [GNUPG:] SIG_CREATED D 22 10 00 1795000000 AAAA
        [GNUPG:] INV_RECP 1 nobody@example.org
        [GNUPG:] DECRYPTION_FAILED
        [GNUPG:] ERROR pkdecrypt_failed 33554443
        [GNUPG:] PINENTRY_LAUNCHED 123 curses 1.2 - - - - 0/0 0
        """
        let lines = GPGStatusParser.parse(out)
        XCTAssertEqual(lines.count, 14)
        XCTAssertEqual(lines[1].status, .goodSig(keyID: "1234567890ABCDEF", userID: "Alice <alice@example.org>"))
        XCTAssertEqual(lines[9].status, .sigCreated(type: "D", pubkeyAlgo: 22, hashAlgo: 10, sigClass: "00", timestamp: "1795000000", fingerprint: "AAAA"))
        XCTAssertEqual(lines[10].status, .invRecp(reason: 1, recipient: "nobody@example.org"))
        XCTAssertEqual(lines[12].status, .error(location: "pkdecrypt_failed", code: 11))
        XCTAssertEqual(lines[13].status, .pinentryLaunched)
        let sigs = GPGStatusParser.signatures(from: lines)
        XCTAssertEqual(sigs.count, 3)
        XCTAssertEqual(sigs[0].status, .good)
        XCTAssertEqual(sigs[0].fingerprint, "AAAA")
        XCTAssertEqual(sigs[0].primaryFingerprint, "BBBB")
        XCTAssertEqual(sigs[0].trust, .ultimate)
        XCTAssertEqual(sigs[0].email, "alice@example.org")
        XCTAssertEqual(sigs[1].status, .noPublicKey)
        XCTAssertEqual(sigs[1].fingerprint, "CCCC")
        XCTAssertEqual(sigs[2].status, .bad)
        XCTAssertEqual(sigs[2].userID, "Bob % <bob@example.org>")
    }

    func testColonsParser() {
        let listing = """
        tru::1:1795000000:0:3:1:5
        pub:u:255:22:AAAABBBBCCCCDDDD:1795000000:1900000000::u:::scESC:::::ed25519:::0:
        fpr:::::::::0123456789ABCDEF0123AAAABBBBCCCCDDDD:
        uid:u::::1795000000::HASH::Alice \\x3a Admin <Alice@Example.org>::::::::::0:
        sub:u:255:18:1111222233334444:1795000000::::::e:::::cv25519::
        fpr:::::::::FFFF1111222233334444FFFF1111222233334444:
        pub:r:3072:1:5555666677778888:1700000000:::-:::sc:::::::
        fpr:::::::::9999:
        uid:r::::1700000000::H2::bob@example.org::::::::::0:
        """
        let keys = GPGColonsParser.parseKeys(listing)
        XCTAssertEqual(keys.count, 2)
        let a = keys[0]
        XCTAssertEqual(a.fingerprint, "0123456789ABCDEF0123AAAABBBBCCCCDDDD")
        XCTAssertEqual(a.keyID, "AAAABBBBCCCCDDDD")
        XCTAssertEqual(a.validity, "u")
        XCTAssertEqual(a.capabilities, KeyCapabilities(sign: true, encrypt: true, certify: true))
        XCTAssertEqual(a.curve, "ed25519")
        XCTAssertEqual(a.expires, Date(timeIntervalSince1970: 1_900_000_000))
        XCTAssertEqual(a.userIDs.first?.uid, "Alice : Admin <Alice@Example.org>")
        XCTAssertEqual(a.userIDs.first?.email, "alice@example.org")
        XCTAssertEqual(a.subkeys.first?.fingerprint, "FFFF1111222233334444FFFF1111222233334444")
        XCTAssertEqual(a.subkeys.first?.capabilities, KeyCapabilities(encrypt: true))
        XCTAssertTrue(a.isUsable)
        XCTAssertTrue(keys[1].isRevoked)
        XCTAssertFalse(keys[1].isUsable)
        XCTAssertEqual(keys[1].emails, ["bob@example.org"])
    }

    func testMicalg() {
        XCTAssertEqual(Micalg.name(forHashAlgorithm: 2), "pgp-sha1")
        XCTAssertEqual(Micalg.name(forHashAlgorithm: 8), "pgp-sha256")
        XCTAssertEqual(Micalg.name(forHashAlgorithm: 9), "pgp-sha384")
        XCTAssertEqual(Micalg.name(forHashAlgorithm: 10), "pgp-sha512")
        XCTAssertEqual(Micalg.name(forHashAlgorithm: 11), "pgp-sha224")
        XCTAssertNil(Micalg.name(forHashAlgorithm: 99))
    }

    func testEmailParsing() {
        XCTAssertEqual(EmailAddress.extract("\"Alice A.\" <Alice@Example.org>"), "alice@example.org")
        XCTAssertEqual(EmailAddress.extract("bob@example.org"), "bob@example.org")
        XCTAssertEqual(EmailAddress.parse("Alice <alice@example.org>").name, "Alice")
    }

    func testLocateGPG() {
        XCTAssertNotNil(GPGRunner.locateGPG(preferred: "/nonexistent/gpg"))
        XCTAssertEqual(GPGRunner.locateGPG(preferred: "/opt/homebrew/bin/gpg")?.path, "/opt/homebrew/bin/gpg")
    }

    func testXPCConstants() {
        XCTAssertEqual(SigilXPC.machServiceName(teamID: "ABCDE12345", prefix: "org.fuchss.sigil"), "ABCDE12345.org.fuchss.sigil.helper")
        XCTAssertEqual(SigilXPC.machServiceName(teamID: "ABCDE12345", prefix: "org.fuchss.sigil.dev"), "ABCDE12345.org.fuchss.sigil.dev.helper")
        XCTAssertEqual(SigilXPC.helperBundleID(prefix: "org.fuchss.sigil.dev"), "org.fuchss.sigil.dev.helper")
        XCTAssertEqual(SigilXPC.appGroupID(teamID: "ABCDE12345", prefix: "org.fuchss.sigil"), "ABCDE12345.org.fuchss.sigil")
        XCTAssertEqual(SigilXPC.clientRequirement(teamID: "ABCDE12345", prefix: "org.fuchss.sigil"),
                       "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\" and (identifier \"org.fuchss.sigil\" or identifier \"org.fuchss.sigil.extension\")")
        _ = SigilXPC.makeInterface()
    }
}
