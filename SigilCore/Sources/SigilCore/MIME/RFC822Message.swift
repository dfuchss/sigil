import Foundation

/// An RFC 822 message split into its outer (non `Content-*`) headers and the body entity
/// (`Content-*` headers + blank line + body), as needed for PGP/MIME.
public struct RFC822Message: Sendable {
    public var outerHeaders: [MIMEHeaderField]
    /// The body entity: Content-* headers, a blank line (CRLF), and the raw body bytes.
    public var bodyEntity: Data

    public init(outerHeaders: [MIMEHeaderField], bodyEntity: Data) {
        self.outerHeaders = outerHeaders
        self.bodyEntity = bodyEntity
    }

    /// Splits a raw message.
    public init(data: Data) {
        let b = [UInt8](data)
        let parsed = MIMEHeaders.parse(b, 0, b.count)
        var outer: [MIMEHeaderField] = []
        var entity: [UInt8] = []
        for f in parsed.fields {
            if f.lowercasedName.hasPrefix("content-") {
                entity.append(contentsOf: f.rawCRLF)
            } else {
                outer.append(f)
            }
        }
        entity.append(contentsOf: Bytes.crlf)
        entity.append(contentsOf: b[parsed.bodyStart...])
        self.outerHeaders = outer
        self.bodyEntity = Data(entity)
    }

    /// Recombines outer headers and the body entity. Outer header line endings are normalized to CRLF
    /// and `MIME-Version: 1.0` is added if missing.
    public func serialized() -> Data {
        RFC822Message.combine(outerHeaders: outerHeaders, bodyEntity: bodyEntity)
    }

    public static func combine(outerHeaders: [MIMEHeaderField], bodyEntity: Data) -> Data {
        var out = Data()
        var hasMIMEVersion = false
        for f in outerHeaders {
            if f.lowercasedName == "mime-version" { hasMIMEVersion = true }
            out.append(f.rawCRLF)
        }
        if !hasMIMEVersion { out.append(Data("MIME-Version: 1.0\r\n".utf8)) }
        out.append(bodyEntity)
        return out
    }

    public func header(_ name: String) -> String? {
        let n = name.lowercased()
        return outerHeaders.first { $0.lowercasedName == n }?.value
    }
}
