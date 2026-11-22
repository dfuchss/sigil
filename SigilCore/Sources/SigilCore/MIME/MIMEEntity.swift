import Foundation

/// A parsed MIME entity. All ranges are byte offsets into `source`, the buffer the root was parsed from,
/// so the exact original bytes of every part (e.g. the signed part of multipart/signed) are available.
public struct MIMEEntity: Sendable {
    /// The complete buffer of the root entity (shared by all children, copy-on-write).
    public let source: Data
    /// Range of this entity (headers + body) inside `source`. For a part of a multipart, it excludes the
    /// CRLF preceding the next delimiter (that CRLF belongs to the delimiter, RFC 2046 5.1.1).
    public let range: Range<Int>
    public let headerRange: Range<Int>
    public let bodyRange: Range<Int>
    public let headers: MIMEHeaders
    public let contentType: ContentType
    public let children: [MIMEEntity]
    /// For multiparts: whether the closing delimiter was found.
    public let isTerminated: Bool

    static let maxDepth = 32

    public init(data: Data) {
        let bytes = [UInt8](data)
        self.init(bytes: bytes, source: Data(bytes), start: 0, end: bytes.count, depth: 0)
    }

    init(bytes b: [UInt8], source: Data, start: Int, end: Int, depth: Int) {
        self.source = source
        self.range = start..<end
        let parsed = MIMEHeaders.parse(b, start, end)
        self.headers = MIMEHeaders(parsed.fields)
        self.headerRange = start..<parsed.headerEnd
        self.bodyRange = parsed.bodyStart..<end
        let ct = ContentType(parsing: headers["Content-Type"])
        self.contentType = ct

        if ct.isMultipart, let boundary = ct.boundary, !boundary.isEmpty, depth < MIMEEntity.maxDepth {
            let scan = MIMEEntity.scanParts(b, parsed.bodyStart, end, boundary: boundary)
            self.children = scan.parts.map {
                MIMEEntity(bytes: b, source: source, start: $0.lowerBound, end: $0.upperBound, depth: depth + 1)
            }
            self.isTerminated = scan.closed
        } else {
            self.children = []
            self.isTerminated = true
        }
    }

    /// Finds the byte ranges of the body parts of a multipart body.
    static func scanParts(_ b: [UInt8], _ start: Int, _ end: Int, boundary: String) -> (parts: [Range<Int>], closed: Bool) {
        let delim = Array("--\(boundary)".utf8)
        var parts: [Range<Int>] = []
        var partStart: Int? = nil
        var lineStart = start
        while lineStart < end {
            let lfIndex = Bytes.nextLF(b, from: lineStart, end: end)
            let next = lfIndex < end ? lfIndex + 1 : end
            if Bytes.hasPrefix(b, at: lineStart, end: end, delim) {
                var p = lineStart + delim.count
                var isClose = false
                if p + 1 < end, b[p] == 0x2D, b[p + 1] == 0x2D { isClose = true; p += 2 }
                // Only transport padding (LWSP) may follow on the delimiter line.
                var valid = true
                var q = p
                while q < lfIndex {
                    let c = b[q]
                    if c == Bytes.sp || c == Bytes.tab || (c == Bytes.cr && q == lfIndex - 1) { q += 1; continue }
                    valid = false
                    break
                }
                if valid {
                    if let s = partStart {
                        var e = lineStart
                        if e > s, b[e - 1] == Bytes.lf {
                            e -= 1
                            if e > s, b[e - 1] == Bytes.cr { e -= 1 }
                        }
                        parts.append(s..<max(s, e))
                    }
                    if isClose { return (parts, true) }
                    partStart = next
                }
            }
            lineStart = next
        }
        if let s = partStart, s < end { parts.append(s..<end) }
        return (parts, false)
    }

    // MARK: - Accessors

    /// Exact bytes of the entire entity (headers + body).
    public var rawData: Data { source.subdata(in: range) }
    /// Exact bytes of the header section (without the separating blank line).
    public var rawHeaders: Data { source.subdata(in: headerRange) }
    /// Exact (transfer-encoded) body bytes.
    public var rawBody: Data { source.subdata(in: bodyRange) }

    public var transferEncoding: TransferEncoding { TransferEncoding(header: headers["Content-Transfer-Encoding"]) }

    /// Body with the content-transfer-encoding removed.
    public var decodedBody: Data { transferEncoding.decode(rawBody) }

    /// For text parts: the decoded body converted to a String using the declared charset.
    public var text: String? {
        guard contentType.isText else { return nil }
        return Charset.decodeLenient(decodedBody, charset: contentType.charset)
    }

    public var contentDisposition: ParameterizedHeader? {
        headers["Content-Disposition"].map(ParameterizedHeader.init(parsing:))
    }

    public var filename: String? {
        contentDisposition?.parameters["filename"] ?? contentType.parameters["name"]
    }

    public var isAttachment: Bool { contentDisposition?.value == "attachment" }

    /// All leaf entities in depth-first order.
    public var leaves: [MIMEEntity] {
        children.isEmpty ? [self] : children.flatMap(\.leaves)
    }

    /// Depth-first search including self.
    public func first(where predicate: (MIMEEntity) -> Bool) -> MIMEEntity? {
        if predicate(self) { return self }
        for c in children { if let f = c.first(where: predicate) { return f } }
        return nil
    }

    public var isPGPMIMESigned: Bool {
        contentType.mimeType == "multipart/signed"
            && contentType.parameter("protocol")?.lowercased() == "application/pgp-signature"
    }

    public var isPGPMIMEEncrypted: Bool {
        contentType.mimeType == "multipart/encrypted"
            && contentType.parameter("protocol")?.lowercased() == "application/pgp-encrypted"
    }
}
