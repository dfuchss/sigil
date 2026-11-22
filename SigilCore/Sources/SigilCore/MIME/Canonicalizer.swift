import Foundation

/// Makes a MIME entity safe for signing (RFC 3156 section 3): 7-bit clean, CRLF line endings,
/// no trailing whitespace, no lines starting with "From ", lines of at most 76 characters.
public enum Canonicalizer {
    public static let maxLineLength = 76

    /// Canonicalizes a MIME entity (headers + blank line + body).
    public static func canonicalize(entity: Data) -> Data {
        canonicalize(MIMEEntity(data: entity), depth: 0)
    }

    static func canonicalize(_ e: MIMEEntity, depth: Int) -> Data {
        let headerFields = e.headers.fields

        if e.contentType.isMultipart, let boundary = e.contentType.boundary, !e.children.isEmpty, depth < MIMEEntity.maxDepth {
            var out = Data()
            for f in headerFields where f.lowercasedName != "content-transfer-encoding" {
                out.append(f.rawCRLF)
            }
            out.append(Data(Bytes.crlf))
            let parts = e.children.map { canonicalize($0, depth: depth + 1) }
            out.append(MIMEBuilder.multipartBody(parts: parts, boundary: boundary))
            return out
        }

        let body = e.rawBody
        let cte = e.transferEncoding
        let isText = e.contentType.isText || e.headers["Content-Type"] == nil
        var newCTE: TransferEncoding? = nil   // nil: keep header as is
        var newBody: Data

        switch cte {
        case .base64:
            newBody = LineEndings.toCRLF(body)
        case .quotedPrintable:
            let decoded = QuotedPrintable.decode(body)
            newBody = QuotedPrintable.encodeText(decoded)
            if !isText && containsBareLineBreaks(decoded) {
                // Binary content in QP: line breaks were encoded; re-encoding as text would alter it.
                newBody = Base64.encode(decoded)
                newCTE = .base64
            } else {
                newCTE = .quotedPrintable
            }
        case .sevenBit, .eightBit, .binary:
            if e.contentType.type == "message" {
                newBody = canonicalizeEmbeddedMessage(body)
                newCTE = Bytes.isSevenBitClean(newBody) ? .sevenBit : nil
            } else if isText {
                let normalized = LineEndings.toCRLF(body)
                if isSafeSevenBit(normalized) {
                    newBody = normalized
                    newCTE = cte == .sevenBit ? nil : .sevenBit
                } else {
                    newBody = QuotedPrintable.encodeText(body)
                    newCTE = .quotedPrintable
                }
            } else if cte == .sevenBit && isSafeSevenBit(LineEndings.toCRLF(body)) {
                newBody = LineEndings.toCRLF(body)
            } else {
                newBody = Base64.encode(body)
                newCTE = .base64
            }
        }

        var out = Data()
        var hasContentType = false
        for f in headerFields {
            if f.lowercasedName == "content-type" { hasContentType = true }
            if newCTE != nil && f.lowercasedName == "content-transfer-encoding" { continue }
            out.append(f.rawCRLF)
        }
        if !hasContentType {
            let charset = Bytes.isSevenBitClean(body) ? "us-ascii" : "utf-8"
            out.append(Data("Content-Type: text/plain; charset=\(charset)\r\n".utf8))
        }
        if let newCTE, newCTE != .sevenBit || headerFields.contains(where: { $0.lowercasedName == "content-transfer-encoding" }) {
            out.append(Data("Content-Transfer-Encoding: \(newCTE.rawValue)\r\n".utf8))
        }
        out.append(Data(Bytes.crlf))
        out.append(newBody)
        return out
    }

    /// True if every line is 7-bit, ≤ 76 chars, has no trailing whitespace and does not start with "From ".
    static func isSafeSevenBit(_ data: Data) -> Bool {
        let b = [UInt8](data)
        guard Bytes.isSevenBitClean(b) else { return false }
        let from = Array("From ".utf8)
        for (s, e, next) in Bytes.lines(b, 0, b.count) {
            if e - s > maxLineLength { return false }
            if e > s, b[e - 1] == Bytes.sp || b[e - 1] == Bytes.tab { return false }
            if Bytes.hasPrefix(b, at: s, end: e, from) { return false }
            // A bare CR inside a line is not canonical.
            if b[s..<e].contains(Bytes.cr) { return false }
            _ = next
        }
        return true
    }

    static func containsBareLineBreaks(_ data: Data) -> Bool {
        let b = [UInt8](data)
        for i in 0..<b.count {
            if b[i] == Bytes.lf && (i == 0 || b[i - 1] != Bytes.cr) { return true }
            if b[i] == Bytes.cr && (i + 1 >= b.count || b[i + 1] != Bytes.lf) { return true }
        }
        return false
    }

    static func canonicalizeEmbeddedMessage(_ body: Data) -> Data {
        let msg = RFC822Message(data: body)
        var out = Data()
        for f in msg.outerHeaders { out.append(f.rawCRLF) }
        out.append(canonicalize(entity: msg.bodyEntity))
        return out
    }
}
