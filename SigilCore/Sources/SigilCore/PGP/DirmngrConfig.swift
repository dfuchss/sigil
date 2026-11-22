import Foundation

/// The keyserver setting of dirmngr (`<homedir>/dirmngr.conf`), as gpg sees it.
public struct KeyserverStatus: Codable, Sendable, Equatable {
    /// Path of dirmngr.conf (it may not exist).
    public var configPath: String
    /// The effective keyserver URL, nil when none is configured (empty value or the `hkps://none` placeholder).
    public var keyserver: String?
    /// The keyserver a fix would configure.
    public var suggested: String

    public var isConfigured: Bool { keyserver != nil }

    public init(configPath: String, keyserver: String?, suggested: String = DirmngrConfig.suggestedKeyserver) {
        self.configPath = configPath
        self.keyserver = keyserver
        self.suggested = suggested
    }
}

/// Reading and rewriting the `keyserver` option of dirmngr.conf (pure text functions, testable).
public enum DirmngrConfig {
    public static let suggestedKeyserver = "hkps://keys.openpgp.org"
    /// The line a fix appends.
    public static var suggestedLine: String { "keyserver \(suggestedKeyserver)" }
    static let option = "keyserver"

    /// The keyserver from `gpgconf --list-options dirmngr` output; nil for an empty value or the `none` placeholder.
    /// The line is `keyserver:flags:level:desc:type:alttype:argname:default:argdefault:value`; a string value is
    /// quoted with a leading `"` and percent-escaped (`%3a` for `:`).
    public static func keyserver(fromGPGConfOptions output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: ":", maxSplits: 9, omittingEmptySubsequences: false).map(String.init)
            guard fields.first == option, fields.count > 9 else { continue }
            var value = fields[9]
            if value.hasPrefix("\"") { value.removeFirst() }
            value = (value.removingPercentEncoding ?? value).trimmingCharacters(in: .whitespaces)
            return isUsable(value) ? value : nil
        }
        return nil
    }

    /// False for an empty value and for `hkps://none` (GnuPG's "no keyserver" placeholder).
    public static func isUsable(_ url: String) -> Bool {
        let value = url.trimmingCharacters(in: .whitespaces).lowercased()
        return !value.isEmpty && value != "none" && !value.hasSuffix("://none")
    }

    /// `text` with active `keyserver` lines that point to none commented out and `keyserver hkps://keys.openpgp.org`
    /// appended; everything else is kept.
    public static func addingKeyserver(to text: String) -> String {
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if lines.last == "" { lines.removeLast() }
        lines = lines.map { line in
            if let value = optionValue(line), !isUsable(value) { return "# \(line)  # disabled by Sigil" }
            return line
        }
        lines.append(suggestedLine)
        return lines.joined(separator: "\n") + "\n"
    }

    public static func status(configURL: URL, keyserver: String?) -> KeyserverStatus {
        KeyserverStatus(configPath: configURL.path, keyserver: keyserver)
    }

    private static func optionValue(_ line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix(option), !trimmed.hasPrefix("#") else { return nil }
        let rest = trimmed.dropFirst(option.count)
        guard let first = rest.first, first == " " || first == "\t" else { return nil }
        return rest.trimmingCharacters(in: .whitespaces)
    }
}
