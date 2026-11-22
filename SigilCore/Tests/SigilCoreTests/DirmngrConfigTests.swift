import Foundation
import XCTest
@testable import SigilCore

final class DirmngrConfigTests: XCTestCase {
    func testParsingGPGConfOptions() {
        XCTAssertNil(DirmngrConfig.keyserver(fromGPGConfOptions: "keyserver:16:0:use keyserver at URL:1:1:URL:\"hkps%3a//none::\n"))
        XCTAssertNil(DirmngrConfig.keyserver(fromGPGConfOptions: "keyserver:16:0:x:1:1:URL:\"hkps%3a//none::\"hkps%3a//none\n"))
        XCTAssertNil(DirmngrConfig.keyserver(fromGPGConfOptions: ""))
        XCTAssertEqual(DirmngrConfig.keyserver(fromGPGConfOptions:
            "keyserver:16:0:x:1:1:URL:\"hkps%3a//none::\"hkps%3a//keys.openpgp.org\n"), "hkps://keys.openpgp.org")
    }

    func testAddingKeyserverKeepsContentAndDisablesNone() {
        XCTAssertEqual(DirmngrConfig.addingKeyserver(to: ""), "keyserver hkps://keys.openpgp.org\n")
        let fixed = DirmngrConfig.addingKeyserver(to: "verbose\nkeyserver hkps://none\n# keyserver foo\n")
        XCTAssertEqual(fixed, "verbose\n# keyserver hkps://none  # disabled by Sigil\n# keyserver foo\nkeyserver hkps://keys.openpgp.org\n")
    }

    /// Runs against a throw-away GnuPG home only.
    func testServiceStatusAndFixInTemporaryHome() throws {
        let home = try TestKeyring.makeHome()
        defer {
            _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", home.path, "--kill", "all"])
            try? FileManager.default.removeItem(at: home)
        }
        guard FileManager.default.isExecutableFile(atPath: TestKeyring.gpgPath) else { throw XCTSkip("gpg not installed") }
        let service = GPGService(runner: GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: home))
        let before = try service.keyserverStatus()
        XCTAssertFalse(before.isConfigured)
        let configURL = home.appendingPathComponent("dirmngr.conf")
        XCTAssertEqual(URL(fileURLWithPath: before.configPath).resolvingSymlinksInPath(), configURL.resolvingSymlinksInPath())

        let after = try service.fixKeyserver()
        XCTAssertEqual(after.keyserver, "hkps://keys.openpgp.org")
        XCTAssertEqual(try String(contentsOf: configURL, encoding: .utf8), "keyserver hkps://keys.openpgp.org\n")
        // Idempotent: a configured keyserver is not touched again.
        _ = try service.fixKeyserver()
        XCTAssertEqual(try String(contentsOf: configURL, encoding: .utf8), "keyserver hkps://keys.openpgp.org\n")
    }
}
