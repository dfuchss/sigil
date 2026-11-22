import Foundation
import XCTest
@testable import SigilCore

final class GPGAgentConfigTests: XCTestCase {
    func testPinentryProgramParsing() {
        XCTAssertNil(GPGAgentConfig.pinentryProgram(in: ""))
        XCTAssertNil(GPGAgentConfig.pinentryProgram(in: "# pinentry-program /x/pinentry-mac\npinentry-programs /y\n"))
        let text = "default-cache-ttl 600\npinentry-program /usr/bin/pinentry-curses\n  pinentry-program\t/opt/homebrew/bin/pinentry-mac  \n"
        XCTAssertEqual(GPGAgentConfig.pinentryProgram(in: text), "/opt/homebrew/bin/pinentry-mac")
        XCTAssertTrue(GPGAgentConfig.isPinentryMac("/opt/homebrew/bin/pinentry-mac"))
        XCTAssertFalse(GPGAgentConfig.isPinentryMac("/usr/bin/pinentry-curses"))
    }

    func testSettingPinentryProgramKeepsOtherOptions() {
        let text = "default-cache-ttl 600\npinentry-program /usr/bin/pinentry-curses\n"
        let fixed = GPGAgentConfig.settingPinentryProgram("/opt/homebrew/bin/pinentry-mac", in: text)
        XCTAssertEqual(fixed, "default-cache-ttl 600\n# pinentry-program /usr/bin/pinentry-curses  # disabled by Sigil\n"
                       + "pinentry-program /opt/homebrew/bin/pinentry-mac\n")
        XCTAssertEqual(GPGAgentConfig.pinentryProgram(in: fixed), "/opt/homebrew/bin/pinentry-mac")
        XCTAssertEqual(GPGAgentConfig.settingPinentryProgram("/p", in: ""), "pinentry-program /p\n")
    }

    /// Runs against a throw-away GnuPG home only.
    func testServiceStatusAndFixInTemporaryHome() throws {
        guard GPGAgentConfig.locatePinentryMac() != nil else { throw XCTSkip("pinentry-mac not installed") }
        let home = try TestKeyring.makeHome()
        defer {
            _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", home.path, "--kill", "all"])
            try? FileManager.default.removeItem(at: home)
        }
        let configURL = home.appendingPathComponent("gpg-agent.conf")
        try Data("max-cache-ttl 7200\npinentry-program /usr/bin/false\n".utf8).write(to: configURL)
        let service = GPGService(runner: GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: home))

        let before = try service.pinentryStatus()
        XCTAssertEqual(URL(fileURLWithPath: before.configPath).resolvingSymlinksInPath(), configURL.resolvingSymlinksInPath())
        XCTAssertEqual(before.pinentryProgram, "/usr/bin/false")
        XCTAssertFalse(before.usesPinentryMac)

        var replyJSON: Data?
        service.fixPinentry { data, error in replyJSON = data; XCTAssertNil(error) }
        let after = try SigilJSON.decoder().decode(PinentryStatus.self, from: try XCTUnwrap(replyJSON))
        XCTAssertTrue(after.usesPinentryMac)
        XCTAssertEqual(after.pinentryProgram, after.pinentryMacPath)
        XCTAssertTrue(try String(contentsOf: configURL, encoding: .utf8).hasPrefix("max-cache-ttl 7200\n"))
    }
}
