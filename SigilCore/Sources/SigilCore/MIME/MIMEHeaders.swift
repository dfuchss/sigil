import Foundation

/// One header field. `raw` holds the exact original bytes including folding and the line terminator.
public struct MIMEHeaderField: Sendable, Equatable {
    public let name: String
    /// Unfolded, trimmed value.
    public let value: String
    public let raw: Data

    public init(name: String, value: String, raw: Data) {
        self.name = name
        self.value = value
        self.raw = raw
    }

    /// Builds a new field serialized as `Name: value\r\n`.
    public init(name: String, value: String) {
        self.name = name
        self.value = value
        self.raw = Data("\(name): \(value)\r\n".utf8)
    }

    public var lowercasedName: String { name.lowercased() }

    /// `raw` with all line endings normalized to CRLF and guaranteed to end with CRLF.
    public var rawCRLF: Data {
        var b = Bytes.normalizeCRLF([UInt8](raw))
        if !(b.count >= 2 && b[b.count - 2] == Bytes.cr && b[b.count - 1] == Bytes.lf) {
            b.append(contentsOf: Bytes.crlf)
        }
        return Data(b)
    }
}

public struct MIMEHeaders: Sendable, Equatable {
    public var fields: [MIMEHeaderField]

    public init(_ fields: [MIMEHeaderField] = []) { self.fields = fields }

    /// First value of the named header (case-insensitive).
    public subscript(name: String) -> String? {
        let n = name.lowercased()
        return fields.first { $0.lowercasedName == n }?.value
    }

    public func values(_ name: String) -> [String] {
        let n = name.lowercased()
        return fields.filter { $0.lowercasedName == n }.map(\.value)
    }

    struct ParseResult {
        var fields: [MIMEHeaderField]
        /// Index where the header section ends (start of the blank line, or of the body if none).
        var headerEnd: Int
        /// Index of the first body byte.
        var bodyStart: Int
    }

    /// Parses the header section of `b[start..<end]`.
    static func parse(_ b: [UInt8], _ start: Int, _ end: Int) -> ParseResult {
        var fields: [MIMEHeaderField] = []
        var curStart: Int? = nil       // raw start of the current field
        var curValue: [UInt8] = []
        var curName = ""
        var i = start

        func flush(upTo rawEnd: Int) {
            guard let s = curStart else { return }
            let value = Bytes.string(curValue).trimmingCharacters(in: .whitespaces)
            fields.append(MIMEHeaderField(name: curName, value: value, raw: Data(b[s..<rawEnd])))
            curStart = nil
            curValue = []
        }

        while i < end {
            let lfIndex = Bytes.nextLF(b, from: i, end: end)
            var ce = lfIndex
            if lfIndex < end, ce > i, b[ce - 1] == Bytes.cr { ce -= 1 }
            let next = lfIndex < end ? lfIndex + 1 : end

            if ce == i {
                // Blank line: end of header section.
                flush(upTo: i)
                return ParseResult(fields: fields, headerEnd: i, bodyStart: next)
            }
            if b[i] == Bytes.sp || b[i] == Bytes.tab {
                if curStart != nil {
                    curValue.append(contentsOf: b[i..<ce])
                    i = next
                    continue
                }
                // Continuation without a field: not a header section.
                flush(upTo: i)
                return ParseResult(fields: fields, headerEnd: i, bodyStart: i)
            }
            guard let colon = b[i..<ce].firstIndex(of: 0x3A), colon > i else {
                // Not a header line: header section ends without a blank line.
                flush(upTo: i)
                return ParseResult(fields: fields, headerEnd: i, bodyStart: i)
            }
            flush(upTo: i)
            curStart = i
            curName = Bytes.string(b[i..<colon]).trimmingCharacters(in: .whitespaces)
            curValue = Array(b[(colon + 1)..<ce])
            i = next
        }
        flush(upTo: end)
        return ParseResult(fields: fields, headerEnd: end, bodyStart: end)
    }
}

/// A structured header value such as Content-Type or Content-Disposition:
/// a token plus parameters, with RFC 2231 continuations and charsets resolved.
public struct ParameterizedHeader: Sendable, Equatable {
    /// Lowercased main value (e.g. `multipart/signed`, `attachment`).
    public var value: String
    /// Parameters keyed by lowercased name.
    public var parameters: [String: String]

    public init(value: String, parameters: [String: String] = [:]) {
        self.value = value
        self.parameters = parameters
    }

    public init(parsing header: String) {
        let segments = ParameterizedHeader.splitSegments(header)
        value = (segments.first ?? "").trimmingCharacters(in: .whitespaces).lowercased()
        var raw: [(String, String)] = []
        for seg in segments.dropFirst() {
            guard let eq = seg.firstIndex(of: "=") else { continue }
            let name = seg[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let v = ParameterizedHeader.unquote(seg[seg.index(after: eq)...].trimmingCharacters(in: .whitespaces))
            if !name.isEmpty { raw.append((name, v)) }
        }
        parameters = ParameterizedHeader.resolveRFC2231(raw)
    }

    /// Splits on `;` outside quoted strings and drops comments.
    static func splitSegments(_ s: String) -> [String] {
        var segments: [String] = []
        var cur = ""
        var inQuote = false
        var escape = false
        var commentDepth = 0
        for ch in s {
            if escape { cur.append(ch); escape = false; continue }
            if inQuote {
                if ch == "\\" { cur.append(ch); escape = true; continue }
                if ch == "\"" { inQuote = false }
                cur.append(ch)
                continue
            }
            if commentDepth > 0 {
                if ch == "(" { commentDepth += 1 } else if ch == ")" { commentDepth -= 1 }
                continue
            }
            switch ch {
            case "\"": inQuote = true; cur.append(ch)
            case "(": commentDepth = 1
            case ";": segments.append(cur); cur = ""
            default: cur.append(ch)
            }
        }
        segments.append(cur)
        return segments.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty || segments.count == 1 }
    }

    static func unquote(_ s: String) -> String {
        guard s.count >= 2, s.hasPrefix("\""), s.hasSuffix("\"") else { return s }
        var out = ""
        var escape = false
        for ch in s.dropFirst().dropLast() {
            if escape { out.append(ch); escape = false } else if ch == "\\" { escape = true } else { out.append(ch) }
        }
        return out
    }

    /// Resolves RFC 2231 parameter continuations (`name*0`, `name*1*`) and extended values (`name*`).
    static func resolveRFC2231(_ raw: [(String, String)]) -> [String: String] {
        var plain: [String: String] = [:]
        // base name -> [(index, value, extended)]
        var segments: [String: [(Int, String, Bool)]] = [:]
        for (name, value) in raw {
            guard let star = name.firstIndex(of: "*") else {
                if plain[name] == nil { plain[name] = value }
                continue
            }
            let base = String(name[..<star])
            var rest = String(name[name.index(after: star)...])
            var extended = false
            var index = 0
            if rest.isEmpty {
                extended = true // name*=charset'lang'value
            } else {
                if rest.hasSuffix("*") { extended = true; rest.removeLast() }
                guard let n = Int(rest) else { continue }
                index = n
            }
            segments[base, default: []].append((index, value, extended))
        }
        var result = plain
        for (base, segs) in segments {
            let sorted = segs.sorted { $0.0 < $1.0 }
            var bytes: [UInt8] = []
            var charset: String? = nil
            for (i, seg) in sorted.enumerated() {
                var v = seg.1
                if seg.2 {
                    if i == 0 {
                        // charset'language'value
                        let parts = v.split(separator: "'", maxSplits: 2, omittingEmptySubsequences: false)
                        if parts.count == 3 {
                            charset = String(parts[0])
                            v = String(parts[2])
                        }
                    }
                    bytes.append(contentsOf: percentDecode(v))
                } else {
                    bytes.append(contentsOf: Array(v.utf8))
                }
            }
            result[base] = Charset.decode(Data(bytes), charset: charset) ?? Bytes.string(bytes)
        }
        return result
    }

    static func percentDecode(_ s: String) -> [UInt8] {
        let u = Array(s.utf8)
        var out: [UInt8] = []
        var i = 0
        while i < u.count {
            if u[i] == 0x25, i + 2 < u.count, let h = hexValue(u[i + 1]), let l = hexValue(u[i + 2]) {
                out.append(h << 4 | l)
                i += 3
            } else {
                out.append(u[i])
                i += 1
            }
        }
        return out
    }

    static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x41 + 10
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }
}

public struct ContentType: Sendable, Equatable {
    public var type: String
    public var subtype: String
    public var parameters: [String: String]

    public init(type: String, subtype: String, parameters: [String: String] = [:]) {
        self.type = type.lowercased()
        self.subtype = subtype.lowercased()
        self.parameters = parameters
    }

    public init(parsing header: String?) {
        guard let header, !header.trimmingCharacters(in: .whitespaces).isEmpty else {
            self = .defaultText
            return
        }
        let p = ParameterizedHeader(parsing: header)
        let parts = p.value.split(separator: "/", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        if parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty {
            self.init(type: parts[0], subtype: parts[1], parameters: p.parameters)
        } else {
            self = .defaultText
        }
    }

    public static let defaultText = ContentType(type: "text", subtype: "plain", parameters: ["charset": "us-ascii"])

    public var mimeType: String { "\(type)/\(subtype)" }
    public var isMultipart: Bool { type == "multipart" }
    public var isText: Bool { type == "text" }
    public var boundary: String? { parameters["boundary"] }
    public var charset: String? { parameters["charset"] }
    public func parameter(_ name: String) -> String? { parameters[name.lowercased()] }
}
