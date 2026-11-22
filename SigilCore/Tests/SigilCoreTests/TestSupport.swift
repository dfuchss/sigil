import Foundation
import XCTest
@testable import SigilCore

enum Fixtures {
    static func data(_ name: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: "eml", subdirectory: "Fixtures") else {
            throw NSError(domain: "Fixtures", code: 1, userInfo: [NSLocalizedDescriptionKey: "missing fixture \(name)"])
        }
        return try Data(contentsOf: url)
    }
}

struct CLIResult {
    let exitCode: Int32
    let stdout: Data
    let stderr: String
}

/// Runs a command line tool synchronously (test helper, independent from GPGRunner).
func runCLI(_ path: String, _ args: [String], stdin: Data? = nil) throws -> CLIResult {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
    p.standardInput = inPipe
    p.standardOutput = outPipe
    p.standardError = errPipe
    try p.run()
    let outH = outPipe.fileHandleForReading, errH = errPipe.fileHandleForReading
    let outBox = DataBox(), errBox = DataBox()
    let g = DispatchGroup()
    g.enter(); DispatchQueue.global().async { outBox.set((try? outH.readToEnd()) ?? Data()); g.leave() }
    g.enter(); DispatchQueue.global().async { errBox.set((try? errH.readToEnd()) ?? Data()); g.leave() }
    if let stdin { try? inPipe.fileHandleForWriting.write(contentsOf: stdin) }
    try? inPipe.fileHandleForWriting.close()
    p.waitUntilExit()
    g.wait()
    return CLIResult(exitCode: p.terminationStatus, stdout: outBox.get(),
                     stderr: String(decoding: errBox.get(), as: UTF8.self))
}

/// A throw-away GnuPG home with Alice and Bob (and a separate home with Mallory, unknown to the first).
final class TestKeyring: Sendable {
    static let gpgPath = GPGRunner.locateGPG(preferred: nil)?.path ?? "/opt/homebrew/bin/gpg"

    let home: URL
    let otherHome: URL
    let alice: String
    let bob: String
    let mallory: String

    init() throws {
        home = try TestKeyring.makeHome()
        otherHome = try TestKeyring.makeHome()
        alice = try TestKeyring.generate("Alice <alice@example.org>", in: home)
        bob = try TestKeyring.generate("Bob <bob@example.org>", in: home)
        mallory = try TestKeyring.generate("Mallory <mallory@example.org>", in: otherHome)
    }

    var runner: GPGRunner { GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: home, timeout: 30) }
    var otherRunner: GPGRunner { GPGRunner(gpgPath: URL(fileURLWithPath: TestKeyring.gpgPath), homeDir: otherHome, timeout: 30) }

    /// Runs gpg directly on the given home.
    func gpg(_ args: [String], home: URL? = nil, stdin: Data? = nil) throws -> CLIResult {
        try runCLI(TestKeyring.gpgPath, ["--homedir", (home ?? self.home).path, "--batch", "--no-tty"] + args, stdin: stdin)
    }

    func cleanup() {
        for h in [home, otherHome] {
            _ = try? runCLI("/opt/homebrew/bin/gpgconf", ["--homedir", h.path, "--kill", "all"])
            try? FileManager.default.removeItem(at: h)
        }
    }

    static func makeHome() throws -> URL {
        var template = Array("/tmp/sigil-XXXXXX".utf8CString)
        guard let p = mkdtemp(&template) else { throw NSError(domain: "TestKeyring", code: 2) }
        return URL(fileURLWithPath: String(cString: p), isDirectory: true)
    }

    static func generate(_ uid: String, in home: URL) throws -> String {
        let r = try runCLI(gpgPath, ["--homedir", home.path, "--batch", "--no-tty", "--pinentry-mode", "loopback",
                                     "--passphrase", "", "--quick-gen-key", uid, "default", "default", "never"])
        guard r.exitCode == 0 else {
            throw NSError(domain: "TestKeyring", code: 3, userInfo: [NSLocalizedDescriptionKey: r.stderr])
        }
        let list = try runCLI(gpgPath, ["--homedir", home.path, "--batch", "--with-colons", "--list-keys", uid])
        let text = String(decoding: list.stdout, as: UTF8.self)
        guard let fpr = text.split(separator: "\n").first(where: { $0.hasPrefix("fpr:") })?
            .split(separator: ":", omittingEmptySubsequences: false)[9] else {
            throw NSError(domain: "TestKeyring", code: 4)
        }
        return String(fpr)
    }
}

extension Data {
    var string: String { String(decoding: self, as: UTF8.self) }
}

func sampleMessage(body: String = "Hello Bob,\r\n\r\nthis is a test with Umlauts: \u{00e4}\u{00f6}\u{00fc}.\r\nFrom the desk of Alice.   \r\n",
                   contentType: String = "text/plain; charset=utf-8",
                   cte: String = "8bit") -> Data {
    Data(("From: Alice <alice@example.org>\r\n" +
          "To: Bob <bob@example.org>\r\n" +
          "Subject: Test message\r\n" +
          "Date: Sat, 21 Nov 2026 10:00:00 +0000\r\n" +
          "Message-ID: <test-1@example.org>\r\n" +
          "MIME-Version: 1.0\r\n" +
          "Content-Type: \(contentType)\r\n" +
          "Content-Transfer-Encoding: \(cte)\r\n" +
          "\r\n" + body).utf8)
}
