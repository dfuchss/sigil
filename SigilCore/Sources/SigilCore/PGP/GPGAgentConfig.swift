import Foundation

/// The pinentry setting of gpg-agent (`<homedir>/gpg-agent.conf`).
public struct PinentryStatus: Codable, Sendable, Equatable {
    /// Path of gpg-agent.conf (it may not exist).
    public var configPath: String
    /// The effective `pinentry-program` value, nil when unset (gpg-agent then uses its built-in default).
    public var pinentryProgram: String?
    /// True when `pinentryProgram` points at pinentry-mac.
    public var usesPinentryMac: Bool
    /// An installed pinentry-mac that a fix would configure, nil when none is installed.
    public var pinentryMacPath: String?

    public init(configPath: String, pinentryProgram: String?, usesPinentryMac: Bool, pinentryMacPath: String?) {
        self.configPath = configPath
        self.pinentryProgram = pinentryProgram
        self.usesPinentryMac = usesPinentryMac
        self.pinentryMacPath = pinentryMacPath
    }
}

/// Reading and rewriting the `pinentry-program` option of gpg-agent.conf (pure text functions, testable).
public enum GPGAgentConfig {
    static let option = "pinentry-program"

    /// The value of the last active `pinentry-program` line (gpg-agent uses the last one).
    public static func pinentryProgram(in text: String) -> String? {
        var value: String?
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            if let v = optionValue(line) { value = v }
        }
        return value
    }

    /// `text` with every active `pinentry-program` line commented out and `pinentry-program <path>` appended.
    public static func settingPinentryProgram(_ path: String, in text: String) -> String {
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if lines.last == "" { lines.removeLast() }
        lines = lines.map { optionValue(Substring($0)) == nil ? $0 : "# \($0)  # disabled by Sigil" }
        lines.append("\(option) \(path)")
        return lines.joined(separator: "\n") + "\n"
    }

    public static func isPinentryMac(_ path: String) -> Bool {
        (path as NSString).lastPathComponent == "pinentry-mac"
    }

    /// The first installed pinentry-mac (Homebrew on Apple silicon or Intel, or MacGPG2).
    public static func locatePinentryMac() -> String? {
        ["/opt/homebrew/bin/pinentry-mac", "/usr/local/bin/pinentry-mac",
         "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    public static func status(configURL: URL) -> PinentryStatus {
        let text = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        let program = pinentryProgram(in: text)
        return PinentryStatus(configPath: configURL.path, pinentryProgram: program,
                              usesPinentryMac: program.map(isPinentryMac) ?? false,
                              pinentryMacPath: locatePinentryMac())
    }

    private static func optionValue(_ line: Substring) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix(option), !trimmed.hasPrefix("#") else { return nil }
        let rest = trimmed.dropFirst(option.count)
        guard let first = rest.first, first == " " || first == "\t" else { return nil }
        let value = rest.trimmingCharacters(in: .whitespaces)
        return value.isEmpty ? nil : value
    }
}
