import Foundation
import XCTest
@testable import SigilCore

final class MissingKeyStoreTests: XCTestCase {
    var directory: URL!
    var store: MissingKeyStore!

    let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
    var keyID: String { String(fingerprint.suffix(16)) }

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("sigil-store-\(UUID().uuidString)")
        store = MissingKeyStore(fileURL: directory.appendingPathComponent(MissingKeyStore.fileName))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testEmptyWithoutFile() {
        XCTAssertEqual(store.entries(), [])
    }

    func testMergesByKeyIDThenFingerprint() throws {
        let first = Date(timeIntervalSince1970: 1_000), second = Date(timeIntervalSince1970: 2_000)
        try store.record(keyID: keyID.lowercased(), fingerprint: nil, senderEmail: "alice@example.org",
                         signerUserID: nil, at: first)
        try store.record(keyID: keyID, fingerprint: fingerprint, senderEmail: "alice@example.net",
                         signerUserID: "Alice <alice@example.net>", at: second)
        let entries = store.entries()
        XCTAssertEqual(entries.count, 1)
        let entry = try XCTUnwrap(entries.first)
        XCTAssertEqual(entry.keyID, keyID)
        XCTAssertEqual(entry.fingerprint, fingerprint)
        XCTAssertEqual(entry.id, fingerprint)
        XCTAssertEqual(entry.count, 2)
        XCTAssertEqual(entry.firstSeen, first)
        XCTAssertEqual(entry.lastSeen, second)
        XCTAssertEqual(entry.senderEmail, "alice@example.net")
        XCTAssertEqual(entry.signerUserID, "Alice <alice@example.net>")
    }

    func testDifferentFingerprintsWithSameKeyIDStaySeparate() throws {
        let other = "FFFFFFFFFFFFFFFFFFFFFFFF" + keyID
        try store.record(keyID: keyID, fingerprint: fingerprint, senderEmail: nil, signerUserID: nil)
        try store.record(keyID: keyID, fingerprint: other, senderEmail: nil, signerUserID: nil)
        XCTAssertEqual(Set(store.entries().map(\.id)), [fingerprint, other])
    }

    func testKeyIDDerivedFromFingerprintAndInvalidReferencesIgnored() throws {
        XCTAssertTrue(try store.record(keyID: nil, fingerprint: fingerprint, senderEmail: nil, signerUserID: nil))
        XCTAssertEqual(store.entries().first?.keyID, keyID)
        XCTAssertFalse(try store.record(keyID: "xyz", fingerprint: nil, senderEmail: nil, signerUserID: nil))
        XCTAssertEqual(store.entries().count, 1)
    }

    func testUserIDWithoutEmailIsNotKept() throws {
        try store.record(keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: "Just A Name")
        XCTAssertNil(store.entries().first?.signerUserID)
    }

    func testRemoveDismissedOnly() throws {
        try store.record(keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: nil)
        XCTAssertFalse(try store.removeDismissed(id: keyID), "active entries are not removable")
        XCTAssertEqual(store.entries().count, 1)
        try store.setDismissed(id: keyID, true)
        XCTAssertTrue(try store.removeDismissed(id: keyID))
        XCTAssertEqual(store.entries(), [])
        XCTAssertFalse(try store.removeDismissed(id: keyID))
    }

    func testRemoveAllDismissedKeepsActive() throws {
        let other = "AAAAAAAAAAAAAAAA", third = "BBBBBBBBBBBBBBBB"
        for id in [keyID, other, third] { try store.record(keyID: id, fingerprint: nil, senderEmail: nil, signerUserID: nil) }
        try store.setDismissed(id: keyID, true)
        try store.setDismissed(id: other, true)
        XCTAssertEqual(try store.removeAllDismissed(), 2)
        XCTAssertEqual(store.entries().map(\.id), [third])
        XCTAssertEqual(try store.removeAllDismissed(), 0)
    }

    func testRerecordedAfterRemovalIsNew() throws {
        try store.record(keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: nil,
                         at: Date(timeIntervalSince1970: 1_000))
        try store.record(keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: nil,
                         at: Date(timeIntervalSince1970: 2_000))
        try store.setDismissed(id: keyID, true)
        try store.removeAllDismissed()
        try store.record(keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: nil,
                         at: Date(timeIntervalSince1970: 9_000))
        let entry = try XCTUnwrap(store.entry(id: keyID))
        XCTAssertFalse(entry.dismissed)
        XCTAssertEqual(entry.count, 1)
        XCTAssertEqual(entry.firstSeen, Date(timeIntervalSince1970: 9_000))
    }

    func testDismissedStaysDismissedAndRestore() throws {
        try store.record(keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: nil,
                         at: Date(timeIntervalSince1970: 1_000))
        XCTAssertTrue(try store.setDismissed(id: keyID, true))
        try store.record(keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: nil,
                         at: Date(timeIntervalSince1970: 5_000))
        var entry = try XCTUnwrap(store.entry(id: keyID))
        XCTAssertTrue(entry.dismissed)
        XCTAssertEqual(entry.count, 2)
        XCTAssertEqual(entry.lastSeen, Date(timeIntervalSince1970: 5_000))

        XCTAssertTrue(try store.setDismissed(id: keyID, false))
        entry = try XCTUnwrap(store.entry(id: keyID))
        XCTAssertFalse(entry.dismissed)
        XCTAssertFalse(try store.setDismissed(id: "0000000000000000", true))

        try store.remove(id: keyID)
        XCTAssertEqual(store.entries(), [])
    }

    func testConcurrentWritersLoseNothing() throws {
        let other = MissingKeyStore(fileURL: store.fileURL)
        DispatchQueue.concurrentPerform(iterations: 40) { index in
            try? (index.isMultiple(of: 2) ? store! : other).record(
                keyID: keyID, fingerprint: nil, senderEmail: nil, signerUserID: nil)
        }
        XCTAssertEqual(store.entries().first?.count, 40)
    }

    // MARK: Recorder

    func unknownKeyOutcome(keyID: String?, fingerprint: String? = nil, decoded: Bool = true) -> DecodeOutcome {
        let signer = SignerInfo(fingerprint: fingerprint, keyID: keyID, email: nil, userID: nil, validity: nil,
                                status: .noPublicKey)
        return DecodeOutcome(message: decoded ? Data("x".utf8) : nil, classification: .pgpMimeSigned,
                             encrypted: false, signed: false, partial: false, signers: [signer], error: nil,
                             needsPassphrase: false)
    }

    func testRecorderCountsEachMessageOnce() throws {
        let recorder = MissingKeyRecorder(store: store)
        let message = sampleMessage()
        let outcome = unknownKeyOutcome(keyID: keyID)
        XCTAssertEqual(recorder.record(outcome: outcome, message: message), 1)
        XCTAssertEqual(recorder.record(outcome: outcome, message: message), 0, "repeated decode of the same message")
        XCTAssertEqual(recorder.record(outcome: outcome, message: sampleMessage(body: "Another message\r\n")), 1)
        let entry = try XCTUnwrap(store.entries().first)
        XCTAssertEqual(entry.count, 2)
        XCTAssertEqual(entry.senderEmail, "alice@example.org")

        // Only key data and the sender address are stored.
        let json = try String(contentsOf: store.fileURL, encoding: .utf8)
        XCTAssertFalse(json.contains("Test message"))
        XCTAssertFalse(json.contains("test-1@example.org"))
        XCTAssertFalse(json.contains("Hello"))
    }

    func testRecorderSkipsFailedDecodesAndKnownKeys() {
        let recorder = MissingKeyRecorder(store: store)
        XCTAssertEqual(recorder.record(outcome: unknownKeyOutcome(keyID: keyID, decoded: false), message: sampleMessage()), 0)
        var good = unknownKeyOutcome(keyID: keyID)
        good.signers[0].status = .good
        XCTAssertEqual(recorder.record(outcome: good, message: sampleMessage()), 0)
        XCTAssertEqual(store.entries(), [])
    }

    func testRecorderForgetsOldestHashesBeyondCapacity() {
        let recorder = MissingKeyRecorder(store: store, capacity: 1)
        let outcome = unknownKeyOutcome(keyID: keyID)
        let first = sampleMessage(body: "one\r\n"), second = sampleMessage(body: "two\r\n")
        recorder.record(outcome: outcome, message: first)
        recorder.record(outcome: outcome, message: second)
        recorder.record(outcome: outcome, message: first)
        XCTAssertEqual(store.entries().first?.count, 3)
    }
}

final class KeyFetchMatchTests: XCTestCase {
    func key(fingerprint: String, subkey: String? = nil, userIDs: [String]) -> KeyInfo {
        KeyInfo(fingerprint: fingerprint, keyID: String(fingerprint.suffix(16)), isSecret: false, validity: "-",
                ownerTrust: "-", algorithm: 22, length: 255, curve: nil, created: nil, expires: nil,
                capabilities: KeyCapabilities(sign: true), isDisabled: false,
                userIDs: userIDs.map { UserID(uid: $0, validity: "-") },
                subkeys: subkey.map {
                    [SubkeyInfo(fingerprint: $0, keyID: String($0.suffix(16)), validity: "-", algorithm: 22, length: 255,
                                created: nil, expires: nil, capabilities: KeyCapabilities(sign: true))]
                } ?? [])
    }

    func entry(keyID: String, fingerprint: String? = nil) -> MissingKeyEntry {
        MissingKeyEntry(keyID: keyID, fingerprint: fingerprint, senderEmail: "alice@example.org", signerUserID: nil,
                        firstSeen: Date(), lastSeen: Date(), count: 1, dismissed: false)
    }

    let primary = "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111"
    let subkey = "BBBBBBBBBBBBBBBBBBBBBBBB2222222222222222"

    func testMatchByFingerprintIncludingSubkeys() {
        let k = key(fingerprint: primary, subkey: subkey, userIDs: ["Alice <alice@example.org>"])
        XCTAssertTrue(MissingKeyMatch.matches(k, entry(keyID: "1111111111111111", fingerprint: primary)))
        XCTAssertTrue(MissingKeyMatch.matches(k, entry(keyID: "2222222222222222", fingerprint: subkey)))
        // A known fingerprint must match exactly; an equal key ID is not enough.
        XCTAssertFalse(MissingKeyMatch.matches(k, entry(keyID: "2222222222222222",
                                                        fingerprint: "CCCCCCCCCCCCCCCCCCCCCCCC2222222222222222")))
    }

    func testMatchByKeyID() {
        let k = key(fingerprint: primary, subkey: subkey, userIDs: ["Alice <alice@example.org>"])
        XCTAssertTrue(MissingKeyMatch.matches(k, entry(keyID: "2222222222222222")))
        XCTAssertFalse(MissingKeyMatch.matches(k, entry(keyID: "3333333333333333")))
    }

    func testNetworkLookupOnlyWhenAllowed() {
        let runner = GPGRunner(gpgPath: URL(fileURLWithPath: "/usr/bin/false"))
        XCTAssertTrue(runner.baseArguments.contains("--no-auto-key-locate"))
        XCTAssertTrue(runner.baseArguments.contains("--no-auto-key-retrieve"))
        let fetching = runner.baseArguments(allowingKeyLookup: true)
        XCTAssertFalse(fetching.contains("--no-auto-key-locate"))
        XCTAssertFalse(fetching.contains("--no-auto-key-retrieve"))
        XCTAssertFalse(fetching.contains { $0.hasPrefix("--keyserver") || $0.hasPrefix("--auto-key-locate") })
    }
}

/// Search and import end to end against temporary GnuPG homes; the network is replaced by `gpg --import` of
/// exported key files, so no network is used.
final class KeySearchIntegrationTests: XCTestCase {
    var keyring: TestKeyring!
    var directory: URL!
    var malloryFile: URL!
    var eve: String!
    var eveFile: URL!

    override func setUpWithError() throws {
        keyring = try TestKeyring()
        directory = try TestKeyring.makeHome()
        eve = try TestKeyring.generate("Mallory (old) <mallory@example.org>", in: keyring.otherHome)
        malloryFile = directory.appendingPathComponent("mallory.asc")
        eveFile = directory.appendingPathComponent("eve.asc")
        try keyring.gpg(["--armor", "--export", keyring.mallory], home: keyring.otherHome).stdout.write(to: malloryFile)
        try keyring.gpg(["--armor", "--export", eve], home: keyring.otherHome).stdout.write(to: eveFile)
    }

    override func tearDownWithError() throws {
        keyring.cleanup()
        try? FileManager.default.removeItem(at: directory)
    }

    func entry(_ fingerprint: String, email: String? = "mallory@example.org") -> MissingKeyEntry {
        MissingKeyEntry(keyID: String(fingerprint.suffix(16)), fingerprint: fingerprint, senderEmail: email,
                        signerUserID: nil, firstSeen: Date(), lastSeen: Date(), count: 1, dismissed: false)
    }

    func store(with entry: MissingKeyEntry) throws -> MissingKeyStore {
        let store = MissingKeyStore(fileURL: directory.appendingPathComponent(MissingKeyStore.fileName))
        try store.record(keyID: entry.keyID, fingerprint: entry.fingerprint, senderEmail: entry.senderEmail, signerUserID: nil)
        return store
    }

    /// A session whose temporary home already holds both of Mallory's keys (as after `--locate-external-keys`).
    func session(entry: MissingKeyEntry, store: MissingKeyStore) throws -> KeySearchSession {
        let files = [malloryFile!, eveFile!]
        return try KeySearchSession(entry: entry, store: store, target: keyring.runner, run: { temp, arguments in
            if arguments.first == "--locate-external-keys" {
                for file in files { _ = try temp.run(["--import", "--", file.path]) }
                return GPGProcessResult(exitCode: 0, stdout: Data(), stderr: Data(), status: [])
            }
            // keyserver: nothing listed
            return GPGProcessResult(exitCode: 0, stdout: Data("info:1:0\n".utf8), stderr: Data(), status: [])
        })
    }

    func targetFingerprints() throws -> Set<String> {
        Set(try keyring.runner.listKeys(secret: false).map(\.fingerprint))
    }

    func testSearchFindsAllKeysAndMarksTheSigningKey() throws {
        let e = entry(keyring.mallory)
        let session = try session(entry: e, store: try store(with: e))
        defer { session.destroy() }
        let result = session.search()
        XCTAssertEqual(Set(result.candidates.map(\.fingerprint)), [keyring.mallory, eve])
        XCTAssertEqual(result.candidates.first?.fingerprint, keyring.mallory, "the signing key is listed first")
        XCTAssertEqual(result.candidates.filter(\.matchesSignature).map(\.fingerprint), [keyring.mallory])
        XCTAssertEqual(result.candidates.first?.sources, ["auto-key-locate"])
        XCTAssertEqual(try targetFingerprints(), [keyring.alice, keyring.bob], "searching never touches the keyring")
    }

    func testImportsOnlyTheChosenFingerprintAndRemovesEntryOnMatch() throws {
        let e = entry(keyring.mallory)
        let store = try store(with: e)
        let session = try session(entry: e, store: store)
        _ = session.search()
        let home = session.home.url

        let result = try session.importKey(fingerprint: keyring.mallory)
        XCTAssertTrue(result.matchesSignature)
        XCTAssertTrue(result.entryRemoved)
        XCTAssertEqual(store.entries(), [])
        XCTAssertEqual(try targetFingerprints(), [keyring.alice, keyring.bob, keyring.mallory], "Eve's key stays out")

        session.destroy()
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.path), "the temporary home is deleted")
        XCTAssertTrue(home.path.hasPrefix("/tmp/sigil-fetch-"))
    }

    func testImportOfNonMatchingKeyKeepsEntry() throws {
        let e = entry(keyring.mallory)
        let store = try store(with: e)
        let session = try session(entry: e, store: store)
        defer { session.destroy() }
        _ = session.search()

        let result = try session.importKey(fingerprint: eve)
        XCTAssertFalse(result.matchesSignature)
        XCTAssertFalse(result.entryRemoved)
        XCTAssertEqual(store.entries().count, 1)
        XCTAssertEqual(try targetFingerprints(), [keyring.alice, keyring.bob, eve])
    }

    func testImportRequiresEmailUserID() throws {
        let nameOnly = try TestKeyring.generate("Just A Name", in: keyring.otherHome)
        let file = directory.appendingPathComponent("name.asc")
        try keyring.gpg(["--armor", "--export", nameOnly], home: keyring.otherHome).stdout.write(to: file)
        let e = entry(nameOnly)
        let session = try KeySearchSession(entry: e, store: try store(with: e), target: keyring.runner,
                                           run: { temp, _ in try temp.run(["--import", "--", file.path]) })
        defer { session.destroy() }
        _ = try session.run(session.temp, [])
        XCTAssertThrowsError(try session.importKey(fingerprint: nameOnly)) {
            XCTAssertTrue(($0 as? KeyFetchError)?.message.contains("no user ID with an email address") == true)
        }
        XCTAssertEqual(try targetFingerprints(), [keyring.alice, keyring.bob])
    }

    func testServiceSearchKeepsSessionUntilDiscarded() throws {
        let e = entry(keyring.mallory)
        let store = try store(with: e)
        let service = GPGService(runner: keyring.runner, missingKeys: MissingKeyRecorder(store: store))
        let result = try service.searchMissingKey(id: e.id) { entry, store in try self.session(entry: entry, store: store) }
        XCTAssertTrue(service.hasSearchSession(result.token))
        _ = try service.importCandidateKey(token: result.token, fingerprint: keyring.mallory)
        service.searches.discard(result.token)
        XCTAssertThrowsError(try service.importCandidateKey(token: result.token, fingerprint: keyring.mallory))
    }

    func testSearchWithNothingFoundReportsGPGErrorAndCleansUp() throws {
        let e = entry(keyring.mallory)
        let session = try KeySearchSession(entry: e, store: try store(with: e), target: keyring.runner, run: { _, _ in
            GPGProcessResult(exitCode: 2, stdout: Data(), stderr: Data("gpg: error searching keyserver: No keyserver available\n".utf8), status: [])
        })
        let home = session.home.url
        let result = session.search()
        session.destroy()
        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertTrue(result.message?.contains("No keyserver available") == true, result.message ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.path))
    }

    func testDecodeRecordsUnknownSigner() throws {
        let store = MissingKeyStore(fileURL: directory.appendingPathComponent(MissingKeyStore.fileName))
        let signed = try PGPMIMEEncoder.sign(message: sampleMessage(), signer: keyring.mallory, gpg: keyring.otherRunner)
        let service = GPGService(runner: keyring.runner, missingKeys: MissingKeyRecorder(store: store))
        for _ in 0..<2 { try service.decodeOutcome(signed) }
        let entry = try XCTUnwrap(store.entries().first)
        XCTAssertEqual(entry.keyID, String(keyring.mallory.suffix(16)))
        XCTAssertEqual(entry.senderEmail, "alice@example.org", "the From address of the message")
        XCTAssertEqual(entry.count, 1)
    }
}

final class KeySearchParsingTests: XCTestCase {
    let sample = """
    info:1:3
    pub:AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111:22:255:1700000000::
    uid:Alice Example <alice@example.org>:1700000000::
    uid:Alice %3a colon <alice@example.net>:1700000001::
    pub:2222222222222222:1:4096:1500000000:1600000000:e
    uid:Old Alice <alice@example.org>:1500000000::
    pub:CCCCCCCCCCCCCCCCCCCCCCCC3333333333333333:22:255:1400000000::r
    uid:Revoked <alice@example.org>:1400000000::r
    """

    func testParsesKeyserverListing() {
        let hits = KeyServerSearchParser.parse(sample)
        XCTAssertEqual(hits.count, 3)
        XCTAssertEqual(hits[0].id, "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111")
        XCTAssertEqual(hits[0].userIDs, ["Alice Example <alice@example.org>", "Alice : colon <alice@example.net>"])
        XCTAssertEqual(hits[0].created, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertFalse(hits[0].expired || hits[0].revoked)
        XCTAssertEqual(hits[1].id, "2222222222222222")
        XCTAssertTrue(hits[1].expired)
        XCTAssertTrue(hits[2].revoked)
    }

    func entry(_ keyID: String, _ fingerprint: String? = nil) -> MissingKeyEntry {
        MissingKeyEntry(keyID: keyID, fingerprint: fingerprint, senderEmail: "alice@example.org", signerUserID: nil,
                        firstSeen: Date(), lastSeen: Date(), count: 1, dismissed: false)
    }

    func testMatchSignatureAndDeduplication() {
        let e = entry("1111111111111111", "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111")
        let hits = KeyServerSearchParser.parse(sample).map { KeyCandidate.make($0, entry: e) }
        XCTAssertEqual(hits.map(\.matchesSignature), [true, false, false])

        // The same key found by WKD (full fingerprint) and listed by the keyserver with its key ID only.
        let wkd = KeyCandidate(fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111", keyID: "1111111111111111",
                               userIDs: [.init(uid: "Alice <alice@example.org>")], created: nil, expired: false,
                               revoked: false, sources: ["auto-key-locate"], matchesSignature: true)
        let idOnly = KeyCandidate(fingerprint: "1111111111111111", keyID: "1111111111111111",
                                  userIDs: [.init(uid: "Alice <alice@example.org>"), .init(uid: "A <a@example.net>")],
                                  created: Date(timeIntervalSince1970: 5), expired: false, revoked: false,
                                  sources: ["keyserver"], matchesSignature: false)
        let merged = KeyCandidate.merge([[wkd], hits + [idOnly]])
        XCTAssertEqual(merged.count, 3)
        let first = merged[0]
        XCTAssertEqual(first.fingerprint, "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111")
        XCTAssertEqual(first.sources, ["auto-key-locate", "keyserver"])
        XCTAssertTrue(first.matchesSignature)
        XCTAssertEqual(first.userIDs.count, 4)
        XCTAssertNotNil(first.created)
    }

    func candidate(sources: [String], matches: Bool = false, expired: Bool = false, revoked: Bool = false,
                   uid: String = "Alice <alice@example.org>") -> KeyCandidate {
        KeyCandidate(fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111", keyID: "1111111111111111",
                     userIDs: [.init(uid: uid)], created: nil, expired: expired, revoked: revoked,
                     sources: sources, matchesSignature: matches)
    }

    func testPreselection() {
        let sender = "Alice@Example.org"
        // Keyserver-only keys are never ticked, not even the signing key (the address is not verified).
        XCTAssertFalse(candidate(sources: ["keyserver"], matches: true).isPreselected(forSender: sender))
        XCTAssertFalse(candidate(sources: ["recv-keys"], matches: true).isPreselected(forSender: sender))
        XCTAssertFalse(candidate(sources: ["keyserver"], matches: true, uid: "Eve <eve@example.org>")
            .isPreselected(forSender: sender))
        XCTAssertTrue(candidate(sources: ["keyserver"], matches: true).isKeyserverOnly)
        // A signing key found through auto-key-locate stays ticked, even without the sender's address.
        XCTAssertTrue(candidate(sources: ["auto-key-locate"], matches: true).isPreselected(forSender: sender))
        XCTAssertTrue(candidate(sources: ["auto-key-locate", "keyserver"], matches: true).isPreselected(forSender: sender))
        XCTAssertFalse(candidate(sources: ["auto-key-locate", "keyserver"]).isKeyserverOnly)
        XCTAssertTrue(candidate(sources: ["auto-key-locate"]).isPreselected(forSender: sender))
        XCTAssertTrue(candidate(sources: ["auto-key-locate", "keyserver"]).isPreselected(forSender: sender))
        XCTAssertFalse(candidate(sources: ["keyserver"]).isPreselected(forSender: sender), "keyserver-only, no match")
        XCTAssertFalse(candidate(sources: ["auto-key-locate"], uid: "Alice <other@example.org>")
            .isPreselected(forSender: sender), "WKD key without the sender's address")
        XCTAssertFalse(candidate(sources: ["auto-key-locate"], matches: true, expired: true).isPreselected(forSender: sender))
        XCTAssertFalse(candidate(sources: ["auto-key-locate"], revoked: true).isPreselected(forSender: sender))
        // "Select all valid": any source, but not expired/revoked and with the sender's address.
        XCTAssertTrue(candidate(sources: ["keyserver"]).isValid(forSender: sender))
        XCTAssertFalse(candidate(sources: ["keyserver"], expired: true).isValid(forSender: sender))
        XCTAssertFalse(candidate(sources: ["keyserver"], uid: "Bob <bob@example.org>").isValid(forSender: sender))
        XCTAssertFalse(candidate(sources: ["keyserver"]).isValid(forSender: nil))
    }
}

final class TempHomeLog: @unchecked Sendable {
    private let lock = NSLock()
    private var value: URL?
    func set(_ url: URL) { lock.lock(); value = url; lock.unlock() }
    var url: URL? { lock.lock(); defer { lock.unlock() }; return value }
}

final class CommandLog: @unchecked Sendable {
    private let lock = NSLock()
    private var commands: [String] = []
    func append(_ command: String) { lock.lock(); commands.append(command); lock.unlock() }
    var entries: [String] { lock.lock(); defer { lock.unlock() }; return commands }
}

extension GPGService {
    /// Calls the XPC entry point synchronously (it replies on the calling thread).
    func decodeOutcome(_ message: Data) throws {
        var failure: String?
        decode(message: message, interactive: false, allowMixed: false) { _, error in failure = error }
        if let failure { throw KeyFetchError(failure) }
    }
}

final class FetchHintTests: XCTestCase {
    func testUnknownKeyBoxHasFetchHint() {
        let unknown = SignerInfo(fingerprint: nil, keyID: "89ABCDEF01234567", email: nil, userID: nil, validity: nil,
                                 status: .noPublicKey)
        let outcome = DecodeOutcome(message: Data(), classification: .pgpMimeSigned, encrypted: false, signed: true,
                                    partial: false, signers: [unknown], error: nil, needsPassphrase: false)
        let box = WarningBox.make(mark: .yellow, headline: "Unknown key", outcome: outcome, signingError: nil)
        XCTAssertTrue(box.plainText.contains("\r\nOpen the Sigil app to fetch this key.\r\n"))
        XCTAssertTrue(box.html.contains("<div>Open the Sigil app to fetch this key.</div>"))
        XCTAssertTrue(box.plainText.hasPrefix("\u{26A0}\u{FE0F} Sigil: "))

        var expired = unknown
        expired.status = .expiredKey
        let other = WarningBox.make(mark: .yellow, headline: "Expired", outcome: DecodeOutcome(
            message: Data(), classification: .pgpMimeSigned, encrypted: false, signed: true, partial: false,
            signers: [expired], error: nil, needsPassphrase: false), signingError: nil)
        XCTAssertFalse(other.plainText.contains("fetch this key"))
    }
}

final class RecipientKeyChoiceTests: XCTestCase {
    func key(_ fingerprint: String, created: TimeInterval, validity: String = "-", subkeyCreated: TimeInterval? = nil,
             expired: Bool = false, uid: String = "Bob <bob@example.org>") -> KeyInfo {
        KeyInfo(fingerprint: fingerprint, keyID: String(fingerprint.suffix(16)), isSecret: false,
                validity: expired ? "e" : "-", ownerTrust: "-", algorithm: 22, length: 255, curve: nil,
                created: Date(timeIntervalSince1970: created), expires: nil,
                capabilities: KeyCapabilities(encrypt: true), isDisabled: false,
                userIDs: [UserID(uid: uid, validity: validity)],
                subkeys: subkeyCreated.map {
                    [SubkeyInfo(fingerprint: fingerprint + "S", keyID: "S", validity: "-", algorithm: 18, length: 255,
                                created: Date(timeIntervalSince1970: $0), expires: nil,
                                capabilities: KeyCapabilities(encrypt: true))]
                } ?? [])
    }

    let a = "AAAA000000000000000000000000000000000001"
    let b = "BBBB000000000000000000000000000000000002"
    let c = "CCCC000000000000000000000000000000000003"

    func choose(_ keys: [KeyInfo], preferred: String? = nil) -> String? {
        RecipientKeyChoice.choose(from: keys, email: "bob@example.org", preferred: preferred)?.fingerprint
    }

    func testPreferredBeatsVerifiedBeatsNewestBeatsFingerprint() {
        let old = key(a, created: 100)
        let verified = key(b, created: 50, validity: "f")
        let newest = key(c, created: 900)
        XCTAssertEqual(choose([old, verified, newest], preferred: a.lowercased()), a, "preferred first")
        XCTAssertEqual(choose([old, verified, newest]), b, "then verified")
        XCTAssertEqual(choose([old, newest]), c, "then newest")
        XCTAssertEqual(choose([key(b, created: 5), key(a, created: 5)]), a, "then the lowest fingerprint")
    }

    func testEncryptionSubkeyCreationDecidesAge() {
        let oldPrimaryNewSub = key(a, created: 10, subkeyCreated: 1000)
        let newPrimary = key(b, created: 500)
        XCTAssertEqual(choose([newPrimary, oldPrimaryNewSub]), a)
    }

    func testUnusablePreferredKeyIsIgnored() {
        let expiredPreferred = key(a, created: 1, expired: true)
        let other = key(b, created: 2)
        XCTAssertEqual(choose([expiredPreferred, other], preferred: a), b)
        let revokedUID = key(a, created: 1, validity: "r")
        XCTAssertEqual(choose([revokedUID, other], preferred: a), b)
        XCTAssertNil(choose([expiredPreferred], preferred: a))
        XCTAssertEqual(choose([key(c, created: 1, uid: "Other <o@example.org>"), other], preferred: c), b,
                       "a preferred key without the address is ignored")
    }
}

final class PreferredKeyStoreTests: XCTestCase {
    func testPersistenceAndClearing() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("sigil-pref-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent(PreferredKeyStore.fileName)
        let store = PreferredKeyStore(fileURL: url)
        XCTAssertEqual(store.all(), [:])
        try store.set(email: "Bob@Example.org", fingerprint: "ab cd")
        XCTAssertEqual(PreferredKeyStore(fileURL: url).fingerprint(for: "bob@EXAMPLE.org"), "ABCD")
        XCTAssertEqual(PreferredKeyStore(fileURL: url).all(), ["bob@example.org": "ABCD"])
        try store.set(email: "bob@example.org", fingerprint: nil)
        XCTAssertEqual(PreferredKeyStore(fileURL: url).all(), [:])
    }
}

final class PreferredKeyServiceTests: XCTestCase {
    func testSetRequiresUsableKeyAndResolveHonoursIt() throws {
        let keyring = try TestKeyring()
        defer { keyring.cleanup() }
        let second = try TestKeyring.generate("Bob Two <bob@example.org>", in: keyring.home)
        let dir = try TestKeyring.makeHome()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = PreferredKeyStore(fileURL: dir.appendingPathComponent(PreferredKeyStore.fileName))
        let service = GPGService(runner: keyring.runner, preferredKeys: store)

        XCTAssertThrowsError(try service.setPreferredKey(email: "bob@example.org", fingerprint: keyring.alice))
        let list = try service.setPreferredKey(email: "bob@example.org", fingerprint: second)
        XCTAssertEqual(list, [PreferredKeyEntry(email: "bob@example.org", fingerprint: second, usable: true)])
        XCTAssertEqual(try service.resolveRecipient("Bob <bob@example.org>")?.fingerprint, second)

        try store.set(email: "bob@example.org", fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567")
        XCTAssertEqual(try service.listPreferredKeys().first?.usable, false)
        XCTAssertNotEqual(try service.resolveRecipient("bob@example.org")?.fingerprint,
                          "0123456789ABCDEF0123456789ABCDEF01234567")
        XCTAssertEqual(try service.setPreferredKey(email: "bob@example.org", fingerprint: nil), [])
    }
}

final class ManualKeySearchTests: XCTestCase {
    func testQueryValidation() {
        XCTAssertEqual(KeyQuery.parse(" Alice@Example.org "), .email("alice@example.org"))
        XCTAssertEqual(KeyQuery.parse("Alice <alice@example.org>"), .email("alice@example.org"))
        XCTAssertEqual(KeyQuery.parse("0x89abcdef01234567"), .keyID("89ABCDEF01234567"))
        let fpr = "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111"
        XCTAssertEqual(KeyQuery.parse(Fingerprint.grouped(fpr)), .fingerprint(fpr))
        XCTAssertEqual(KeyQuery.parse(fpr.lowercased()), .fingerprint(fpr))
        XCTAssertEqual(KeyQuery.parse(String(repeating: "A", count: 64)), .fingerprint(String(repeating: "A", count: 64)))
        for bad in ["", "   ", "alice", "alice@", "12345678", String(repeating: "A", count: 41), "--export-all", "zz@"] {
            XCTAssertNil(KeyQuery.parse(bad), bad)
        }
    }

    func testInvalidQueryDoesNotCallGPG() {
        let service = GPGService(runner: nil)
        XCTAssertThrowsError(try service.searchKeys(query: "not a query")) {
            XCTAssertTrue(($0 as? KeyFetchError)?.message.contains("Enter an email address") == true)
        }
    }

    func candidate(_ fingerprint: String = "AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111", sources: [String],
                   uid: String = "Alice <alice@example.org>", matchesQuery: Bool = false, expired: Bool = false,
                   revoked: Bool = false) -> KeyCandidate {
        KeyCandidate(fingerprint: fingerprint, keyID: String(fingerprint.suffix(16)), userIDs: [.init(uid: uid)],
                     created: nil, expired: expired, revoked: revoked, sources: sources, matchesSignature: false,
                     matchesQuery: matchesQuery)
    }

    func testPreselectionForEmailSearch() {
        let query = KeyQuery.email("alice@example.org")
        XCTAssertTrue(candidate(sources: ["auto-key-locate"]).isPreselected(forQuery: query))
        XCTAssertFalse(candidate(sources: ["keyserver"]).isPreselected(forQuery: query), "keyserver only")
        XCTAssertFalse(candidate(sources: ["auto-key-locate"], uid: "Bob <bob@example.org>").isPreselected(forQuery: query))
        XCTAssertFalse(candidate(sources: ["auto-key-locate"], expired: true).isPreselected(forQuery: query))
        XCTAssertFalse(candidate(sources: ["auto-key-locate"], revoked: true).isPreselected(forQuery: query))
        XCTAssertTrue(candidate(sources: ["keyserver"]).isValid(forQuery: query), "select all valid")
        XCTAssertFalse(candidate(sources: ["keyserver"], expired: true).isValid(forQuery: query))
    }

    func testPreselectionForFingerprintSearch() {
        let query = KeyQuery.fingerprint("AAAAAAAAAAAAAAAAAAAAAAAA1111111111111111")
        XCTAssertTrue(candidate(sources: ["keyserver"], matchesQuery: true).isPreselected(forQuery: query))
        XCTAssertFalse(candidate(sources: ["keyserver"]).isPreselected(forQuery: query))
        XCTAssertFalse(candidate(sources: ["keyserver"], matchesQuery: true, expired: true).isPreselected(forQuery: query))
        XCTAssertTrue(candidate(sources: ["keyserver"]).isValid(forQuery: .keyID("1111111111111111")))
    }

    func testManualSearchEndToEnd() throws {
        let keyring = try TestKeyring()
        defer { keyring.cleanup() }
        let dir = try TestKeyring.makeHome()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("m.asc")
        try keyring.gpg(["--armor", "--export", keyring.mallory], home: keyring.otherHome).stdout.write(to: file)
        let service = GPGService(runner: keyring.runner)
        let make: (KeyQuery) throws -> KeySearchSession = { query in
            try KeySearchSession(query: query, target: keyring.runner, run: { temp, arguments in
                if arguments.first == "--locate-external-keys" || arguments.first == "--recv-keys" {
                    _ = try temp.run(["--import", "--", file.path])
                }
                return GPGProcessResult(exitCode: 0, stdout: Data("info:1:0\n".utf8), stderr: Data(), status: [])
            })
        }

        // Email: WKD result is ticked, nothing is imported yet, no signature marker.
        var result = try service.searchKeys(query: "mallory@example.org", makeSession: make)
        var found = try XCTUnwrap(result.candidates.first)
        XCTAssertEqual(found.fingerprint, keyring.mallory)
        XCTAssertFalse(found.matchesSignature)
        XCTAssertFalse(found.alreadyInKeyring)
        XCTAssertTrue(found.isPreselected(forQuery: .email("mallory@example.org")))
        let imported = try service.importCandidateKey(token: result.token, fingerprint: keyring.mallory)
        XCTAssertFalse(imported.matchesSignature)
        XCTAssertFalse(imported.entryRemoved)
        service.searches.discard(result.token)

        // Fingerprint: exact match preselected, now marked as already in the keyring.
        result = try service.searchKeys(query: keyring.mallory, makeSession: make)
        found = try XCTUnwrap(result.candidates.first)
        XCTAssertTrue(found.matchesQuery)
        XCTAssertTrue(found.alreadyInKeyring)
        XCTAssertTrue(found.isPreselected(forQuery: .fingerprint(keyring.mallory)))
        service.searches.discard(result.token)
    }
}
