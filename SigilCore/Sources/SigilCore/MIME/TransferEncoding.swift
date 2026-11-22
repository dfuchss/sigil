import Foundation

public enum Charset {
    /// Decodes `data` in the named IANA charset. Returns nil if the charset is unknown or the bytes are invalid.
    public static func decode(_ data: Data, charset: String?) -> String? {
        let name = (charset ?? "us-ascii").trimmingCharacters(in: .whitespaces).lowercased()
        switch name {
        case "us-ascii", "ascii", "utf-8", "utf8", "":
            // us-ascii text frequently carries UTF-8 in practice; UTF-8 is a superset of ASCII.
            return String(data: data, encoding: .utf8)
        case "iso-8859-1", "latin1", "latin-1", "l1":
            return String(data: data, encoding: .isoLatin1)
        case "windows-1252", "cp1252":
            return String(data: data, encoding: .windowsCP1252)
        default:
            let cf = CFStringConvertIANACharSetNameToEncoding(name as CFString)
            guard cf != kCFStringEncodingInvalidId else { return nil }
            let ns = CFStringConvertEncodingToNSStringEncoding(cf)
            return String(data: data, encoding: String.Encoding(rawValue: ns))
        }
    }

    /// Decodes with the named charset and falls back to UTF-8, then ISO-8859-1. Never fails.
    public static func decodeLenient(_ data: Data, charset: String?) -> String {
        decode(data, charset: charset) ?? String(data: data, encoding: .utf8) ?? Bytes.string([UInt8](data))
    }
}

public enum TransferEncoding: String, Sendable {
    case sevenBit = "7bit"
    case eightBit = "8bit"
    case binary
    case quotedPrintable = "quoted-printable"
    case base64

    public init(header: String?) {
        let v = (header ?? "7bit").trimmingCharacters(in: .whitespaces).lowercased()
        self = TransferEncoding(rawValue: v) ?? .sevenBit
    }

    public func decode(_ data: Data) -> Data {
        switch self {
        case .base64: return Base64.decode(data)
        case .quotedPrintable: return QuotedPrintable.decode(data)
        default: return data
        }
    }
}

public enum Base64 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    private static let table: [UInt8] = {
        var t = [UInt8](repeating: 0xFF, count: 256)
        for (i, c) in alphabet.enumerated() { t[Int(c)] = UInt8(i) }
        return t
    }()

    /// Lenient decoder: skips characters outside the alphabet, stops at padding.
    public static func decode(_ data: Data) -> Data {
        var out: [UInt8] = []
        out.reserveCapacity(data.count * 3 / 4)
        var acc: UInt32 = 0
        var n = 0
        for c in data {
            if c == 0x3D { break } // '='
            let v = table[Int(c)]
            if v == 0xFF { continue }
            acc = acc << 6 | UInt32(v)
            n += 1
            if n == 4 {
                out.append(UInt8((acc >> 16) & 0xFF))
                out.append(UInt8((acc >> 8) & 0xFF))
                out.append(UInt8(acc & 0xFF))
                acc = 0
                n = 0
            }
        }
        if n == 2 {
            out.append(UInt8((acc >> 4) & 0xFF))
        } else if n == 3 {
            out.append(UInt8((acc >> 10) & 0xFF))
            out.append(UInt8((acc >> 2) & 0xFF))
        }
        return Data(out)
    }

    /// Encodes with CRLF-terminated lines of at most `lineLength` characters.
    public static func encode(_ data: Data, lineLength: Int = 76) -> Data {
        let encoded = Array(data.base64EncodedString().utf8)
        var out: [UInt8] = []
        out.reserveCapacity(encoded.count + encoded.count / lineLength * 2 + 2)
        var i = 0
        while i < encoded.count {
            let e = min(i + lineLength, encoded.count)
            out.append(contentsOf: encoded[i..<e])
            out.append(contentsOf: Bytes.crlf)
            i = e
        }
        return Data(out)
    }
}

public enum QuotedPrintable {
    private static let hex = Array("0123456789ABCDEF".utf8)

    public static func decode(_ data: Data) -> Data {
        let b = [UInt8](data)
        var out: [UInt8] = []
        out.reserveCapacity(b.count)
        let lines = Bytes.lines(b, 0, b.count)
        for (s, e, next) in lines {
            // Strip trailing whitespace (RFC 2045 6.7 rule 3).
            var ce = e
            while ce > s, b[ce - 1] == Bytes.sp || b[ce - 1] == Bytes.tab { ce -= 1 }
            var soft = false
            var i = s
            while i < ce {
                let c = b[i]
                if c == 0x3D {
                    if i + 1 == ce { soft = true; i += 1; continue }
                    if i + 2 < ce,
                       let h = ParameterizedHeader.hexValue(b[i + 1]),
                       let l = ParameterizedHeader.hexValue(b[i + 2]) {
                        out.append(h << 4 | l)
                        i += 3
                        continue
                    }
                }
                out.append(c)
                i += 1
            }
            if !soft && next > e {
                out.append(contentsOf: Bytes.crlf)
            }
        }
        return Data(out)
    }

    /// Encodes text (line breaks become CRLF hard breaks). Lines are at most 76 characters,
    /// trailing whitespace is encoded and lines starting with "From " are protected.
    public static func encodeText(_ data: Data) -> Data {
        let b = [UInt8](data)
        var out: [UInt8] = []
        out.reserveCapacity(b.count + b.count / 8)
        let lines = Bytes.lines(b, 0, b.count)
        for (s, e, next) in lines {
            encodeLine(b, s, e, into: &out)
            if next > e { out.append(contentsOf: Bytes.crlf) }
        }
        return Data(out)
    }

    private static func encodeLine(_ b: [UInt8], _ s: Int, _ e: Int, into out: inout [UInt8]) {
        var lineLen = 0
        var i = s
        let from = Array("From ".utf8)
        while i < e {
            let c = b[i]
            let isLast = i == e - 1
            var token: [UInt8]
            if c == Bytes.sp || c == Bytes.tab {
                token = isLast ? escaped(c) : [c]
            } else if c >= 33 && c <= 126 && c != 0x3D {
                token = [c]
            } else {
                token = escaped(c)
            }
            if i == s && c == 0x2E && isLast { token = escaped(c) }
            // Keep room for a soft break "=" so that physical lines never exceed 76 chars.
            let limit = isLast ? 76 : 75
            if lineLen + token.count > limit {
                out.append(0x3D)
                out.append(contentsOf: Bytes.crlf)
                lineLen = 0
            }
            // Protect physical lines starting with "From " (mbox).
            if lineLen == 0 && c == 0x46 && Bytes.hasPrefix(b, at: i, end: e, from) {
                token = escaped(c)
            }
            out.append(contentsOf: token)
            lineLen += token.count
            i += 1
        }
    }

    private static func escaped(_ c: UInt8) -> [UInt8] {
        [0x3D, hex[Int(c >> 4)], hex[Int(c & 0x0F)]]
    }
}
