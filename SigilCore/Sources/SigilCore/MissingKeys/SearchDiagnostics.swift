import Foundation

/// Why one source (WKD or the keyserver) gave nothing: a plain-text summary plus gpg's own text.
public struct SearchProblem: Codable, Sendable, Equatable, Identifiable {
    public enum Kind: String, Codable, Sendable { case noKeyserver, noWKD, noKeyOnKeyserver, network, other }

    public static let wkd = "WKD"
    public static let keyserver = "keyserver"

    /// `SearchProblem.wkd` or `SearchProblem.keyserver`.
    public var source: String
    public var kind: Kind
    public var summary: String
    /// gpg's own (cleaned) text, for a "Details" disclosure.
    public var details: String

    public var id: String { source }

    public init(source: String, kind: Kind, summary: String, details: String) {
        self.source = source
        self.kind = kind
        self.summary = summary
        self.details = details
    }
}

/// Cleans gpg's stderr of a search and turns known errors into plain text.
public enum SearchDiagnostics {
    /// The `gpg:` lines of `stderr` (prefix removed) without informational noise: keybox / trustdb creation,
    /// "key …: public key … imported" (the key is shown as a candidate) and the import totals.
    public static func cleanedLines(_ stderr: String) -> [String] {
        stderr.split(whereSeparator: \.isNewline)
            .filter { $0.hasPrefix("gpg: ") }
            .map { String($0.dropFirst(5)) }
            .filter { !isNoise($0) }
    }

    static func isNoise(_ line: String) -> Bool {
        if line.hasPrefix("keybox") || line.contains("trustdb created") { return true }
        if line.hasPrefix("key "), line.contains("public key"), line.hasSuffix("imported") { return true }
        if line.hasPrefix("Total number processed") || line.hasPrefix("imported:") || line.hasPrefix("unchanged:") { return true }
        if line.hasPrefix("marginals needed") || line.hasPrefix("depth:") || line.hasPrefix("next trustdb check") { return true }
        return false
    }

    /// The problem of one failed lookup. `email` is the searched address (for the WKD domain), nil for a
    /// fingerprint or key ID search.
    public static func classify(source: String, details: String, email: String?) -> SearchProblem {
        let lower = details.lowercased()
        let domain = email.flatMap { $0.split(separator: "@").last.map(String.init) }
        let target = source == SearchProblem.wkd ? (domain ?? "the web key directory") : "the keyserver"
        func make(_ kind: SearchProblem.Kind, _ summary: String) -> SearchProblem {
            SearchProblem(source: source, kind: kind, summary: summary, details: details)
        }
        if lower.contains("no keyserver available") {
            return make(.noKeyserver, "No keyserver is configured in gpg (dirmngr.conf).")
        }
        let networkWords = ["network error", "connection refused", "connection timed out", "timed out", "timeout",
                            "host not found", "name or service not known", "no route to host", "network is unreachable",
                            "unknown host", "resolve", "dns", "server indicated a failure", "tls", "certificate"]
        if networkWords.contains(where: lower.contains) {
            return make(.network, "Network error while contacting \(target).")
        }
        if source == SearchProblem.wkd, email != nil, lower.contains("general error") || lower.contains("no data") {
            return make(.noWKD, "\(domain ?? "This domain") does not publish keys via WKD (Web Key Directory).")
        }
        if source == SearchProblem.keyserver, lower.contains("no data") || lower.contains("not found") {
            return make(.noKeyOnKeyserver, email != nil ? "The keyserver has no key for this address."
                        : "The keyserver has no key with this ID.")
        }
        return make(.other, details.isEmpty ? "The lookup failed." : details)
    }
}
