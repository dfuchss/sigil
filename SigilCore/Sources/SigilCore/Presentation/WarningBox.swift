import Foundation

/// The warning shown at the top of a message body (Mail renders the decoded body, not its own badge):
/// a `multipart/alternative` entity with a plain-text and an HTML variant.
struct WarningBox: Equatable {
    var mark: MessageMark
    var headline: String
    /// Detail line first, then further problems.
    var lines: [String]
    var signer: String?
    var fingerprint: String?

    static func make(mark: MessageMark, headline: String, outcome: DecodeOutcome, signingError: String?,
                     sender: String? = nil) -> WarningBox {
        var rated: [(kind: SignatureProblem, text: String, signer: SignerInfo)] = []
        for s in outcome.signers {
            if let kind = SignatureProblem.of(s),
               let text = SignerPresentation.problem(of: s, decodeError: outcome.error, sender: sender) {
                rated.append((kind, text, s))
            }
        }
        var lines: [String] = []
        var signer: SignerInfo?
        if let worst = rated.indices.max(by: { rated[$0].kind < rated[$1].kind }) {
            lines.append(rated[worst].text)
            lines += rated.indices.filter { $0 != worst }.map { rated[$0].text }
            signer = rated[worst].signer
        } else if let signingError {
            lines.append(signingError)
        }
        if outcome.signers.contains(where: { $0.status == .noPublicKey }) { lines.append(fetchHint) }
        return WarningBox(mark: mark, headline: headline, lines: lines,
                          signer: signer.map { SignerPresentation(signer: $0, partial: false).label },
                          fingerprint: signer?.fingerprint.map(Fingerprint.grouped))
    }

    /// Added for unknown-key signatures; the helper has put the key on the app's missing-keys list.
    static let fetchHint = "Open the Sigil app to fetch this key."

    var symbol: String { mark == .red ? "\u{26D4}" : "\u{26A0}\u{FE0F}" }

    var plainText: String {
        var out = ["\(symbol) Sigil: \(headline)"]
        out += lines
        if let signer { out.append("Signer: \(signer)") }
        if let fingerprint { out.append("Fingerprint: \(fingerprint)") }
        return out.joined(separator: "\r\n") + "\r\n"
    }

    static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    var html: String {
        let (border, background, text) = mark == .red ? ("#c62828", "#fdecea", "#7f1d1d") : ("#f9a825", "#fff8e1", "#6d4c00")
        var rows = ["<div><b>\(symbol) Sigil: \(Self.escape(headline))</b></div>"]
        rows += lines.map { "<div>\(Self.escape($0))</div>" }
        if let signer { rows.append("<div>Signer: \(Self.escape(signer))</div>") }
        if let fingerprint { rows.append("<div>Fingerprint: \(Self.escape(fingerprint))</div>") }
        let style = "border-left: 4px solid \(border); background: \(background); color: \(text); padding: 10px 14px; "
            + "border-radius: 6px; margin-bottom: 12px; font-family: -apple-system, sans-serif;"
        return "<div style=\"\(style)\">\r\n" + rows.joined(separator: "\r\n") + "\r\n</div>\r\n"
    }

    /// The `multipart/alternative` entity (headers, blank line, body).
    func entity() -> Data {
        let b = "=_SigilBox_" + UUID().uuidString
        let s = "Content-Type: multipart/alternative; boundary=\"\(b)\"\r\n\r\n"
            + "--\(b)\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n\(plainText)"
            + "\r\n--\(b)\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n\(html)"
            + "\r\n--\(b)--\r\n"
        return Data(s.utf8)
    }

    /// `message` with the same outer headers and a `multipart/mixed` body: this box, then the original
    /// body entity unchanged.
    func prepended(to message: Data) -> Data {
        let parsed = RFC822Message(data: message)
        let b = "=_SigilMix_" + UUID().uuidString
        var body = Data("Content-Type: multipart/mixed; boundary=\"\(b)\"\r\n\r\n--\(b)\r\n".utf8)
        body.append(entity())
        body.append(Data("\r\n--\(b)\r\n".utf8))
        body.append(parsed.bodyEntity)
        body.append(Data("\r\n--\(b)--\r\n".utf8))
        return RFC822Message.combine(outerHeaders: parsed.outerHeaders, bodyEntity: body)
    }
}
