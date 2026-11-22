import Foundation
import XCTest
@testable import SigilCore

final class SearchDiagnosticsTests: XCTestCase {
    func testNoiseIsDropped() {
        let stderr = """
        gpg: keybox '/tmp/x/pubring.kbx' created
        gpg: /tmp/x/trustdb.gpg: trustdb created
        gpg: key 0123456789ABCDEF: public key "A <a@example.org>" imported
        gpg: Total number processed: 1
        gpg: error retrieving 'a@example.org' via WKD: General error

        """
        XCTAssertEqual(SearchDiagnostics.cleanedLines(stderr), ["error retrieving 'a@example.org' via WKD: General error"])
    }

    func testClassification() {
        let c = SearchDiagnostics.classify
        XCTAssertEqual(c(SearchProblem.keyserver, "error searching keyserver: No keyserver available", "a@web.de").kind, .noKeyserver)
        let wkd = c(SearchProblem.wkd, "error retrieving 'a@web.de' via WKD: General error; error reading key: General error", "a@web.de")
        XCTAssertEqual(wkd.kind, .noWKD)
        XCTAssertEqual(wkd.summary, "web.de does not publish keys via WKD (Web Key Directory).")
        XCTAssertEqual(c(SearchProblem.keyserver, "error searching keyserver: No data", "a@web.de").summary,
                       "The keyserver has no key for this address.")
        XCTAssertEqual(c(SearchProblem.keyserver, "error searching keyserver: Connection timed out", nil).summary,
                       "Network error while contacting the keyserver.")
        XCTAssertEqual(c(SearchProblem.wkd, "Server indicated a failure", "a@example.org").summary,
                       "Network error while contacting example.org.")
    }

    func testSearchProducesProblemsPerSource() throws {
        let keyring = try TestKeyring()
        let e = MissingKeyEntry(keyID: "0000000000000000", fingerprint: nil, senderEmail: "a@web.de", signerUserID: nil,
                                firstSeen: Date(), lastSeen: Date(), count: 0, dismissed: false)
        let session = try KeySearchSession(entry: e, store: nil, target: keyring.runner, run: { _, args in
            let text = args.first == "--locate-external-keys"
                ? "gpg: keybox 'x' created\ngpg: error retrieving 'a@web.de' via WKD: General error\n"
                : "gpg: error searching keyserver: No keyserver available\n"
            return GPGProcessResult(exitCode: 2, stdout: Data(), stderr: Data(text.utf8), status: [])
        })
        let result = session.search()
        session.destroy()
        XCTAssertEqual(result.problems.map(\.kind), [.noWKD, .noKeyserver])
        XCTAssertFalse(result.problems[0].details.contains("keybox"))
    }
}
