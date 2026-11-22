import Foundation

public enum ArmorKind: String, Sendable, Codable {
    /// `-----BEGIN PGP MESSAGE-----` (encrypted and/or signed binary message).
    case message
    /// `-----BEGIN PGP SIGNED MESSAGE-----` cleartext signature up to `-----END PGP SIGNATURE-----`.
    case signedMessage
}

/// The result of `Armor.scan`.
public struct ArmorScan: Sendable, Equatable {
    public var blocks: [ArmorBlock] = []
    /// A BEGIN line without its END (Mail's truncated previews).
    public var unterminated = false
    /// Above `Armor.maxBlocks` blocks or `Armor.maxScanBytes` of text: not fully scanned.
    public var truncated = false
}

public struct ArmorBlock: Sendable, Equatable {
    public let kind: ArmorKind
    /// Byte range (UTF-8 offsets) of the block from the first `-` of BEGIN to the last `-` of END.
    public let range: Range<Int>
    public let data: Data
}

public enum Armor {
    static let beginMessage = "-----BEGIN PGP MESSAGE-----"
    static let endMessage = "-----END PGP MESSAGE-----"
    static let beginSigned = "-----BEGIN PGP SIGNED MESSAGE-----"
    static let beginSignature = "-----BEGIN PGP SIGNATURE-----"
    static let endSignature = "-----END PGP SIGNATURE-----"

    /// At most this many blocks are taken from one text part, and at most this much text is scanned; a part above
    /// either cap is `ArmorScan.truncated` (treated as PGP, but never handed to gpg).
    public static let maxBlocks = 16
    public static let maxScanBytes = 2 * 1024 * 1024

    /// Finds complete armored message blocks (see `scan`).
    public static func blocks(in data: Data) -> [ArmorBlock] {
        scan(data).blocks
    }

    /// One linear pass over the lines. Markers must start at the beginning of a line (quoted text such as
    /// "> -----BEGIN" is ignored). An open BEGIN waits for its END; a new BEGIN before that abandons it (a real block
    /// cannot contain one: the body is base64, and cleartext-signed text is dash-escaped). `byteLimit` nil scans any
    /// size (PGP/MIME ciphertext parts may be large).
    public static func scan(_ data: Data, byteLimit: Int? = maxScanBytes, blockLimit: Int = maxBlocks) -> ArmorScan {
        let b = [UInt8](data)
        guard Bytes.containsCaseInsensitive(b, "-----BEGIN PGP ") else { return ArmorScan() }
        if let byteLimit, b.count > byteLimit { return ArmorScan(truncated: true) }
        var result = ArmorScan()
        var openStart: Int? = nil
        var openKind: ArmorKind? = nil
        var signatureSeen = false
        let dash = UInt8(ascii: "-")

        for (s, e, _) in Bytes.lines(b, 0, b.count) {
            guard e > s, b[s] == dash else { continue }
            var end = e
            while end > s, b[end - 1] == Bytes.sp || b[end - 1] == Bytes.tab || b[end - 1] == Bytes.cr { end -= 1 }
            let t = Bytes.string(b[s..<end])
            if t == beginMessage || t == beginSigned {
                if openStart != nil { result.unterminated = true }
                openStart = s
                openKind = t == beginMessage ? .message : .signedMessage
                signatureSeen = false
                continue
            }
            guard let start = openStart, let kind = openKind else { continue }
            var close: String? = nil
            switch kind {
            case .message:
                if t == endMessage { close = endMessage }
            case .signedMessage:
                if t == beginSignature { signatureSeen = true } else if signatureSeen && t == endSignature { close = endSignature }
            }
            guard let close else { continue }
            if result.blocks.count == blockLimit {
                result.truncated = true
                return result
            }
            let r = start..<(s + close.utf8.count)
            result.blocks.append(ArmorBlock(kind: kind, range: r, data: Data(b[r])))
            openStart = nil
            openKind = nil
        }
        if openStart != nil { result.unterminated = true }
        return result
    }

    /// Whether a MESSAGE block may hold encrypted data, judged by its first packet: only a signature, one-pass
    /// signature, compressed or literal data packet counts as not encrypted. Anything unreadable counts as encrypted.
    public static func mayBeEncrypted(_ block: ArmorBlock) -> Bool {
        guard block.kind == .message else { return false }
        let lines = Bytes.string([UInt8](block.data)).split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        var index = 1
        while index < lines.count, !lines[index].isEmpty { index += 1 } // armor headers
        index += 1
        guard index < lines.count, lines[index].count >= 4,
              let first = Data(base64Encoded: String(lines[index].prefix(4)))?.first,
              first & 0x80 != 0 else { return true }
        let tag = first & 0x40 != 0 ? first & 0x3F : (first >> 2) & 0x0F
        return ![2, 4, 8, 11].contains(tag)
    }

    public static func blocks(in text: String) -> [ArmorBlock] {
        blocks(in: Data(text.utf8))
    }
}

public enum MessageClassification: String, Sendable, Codable {
    case pgpMimeEncrypted
    case pgpMimeSigned
    case inline
    case none
}

public enum PGPDetector {
    /// Cheap classification: top-level header sniff, then a walk of the MIME tree that only decodes
    /// text/plain parts to look for armor.
    public static func classify(messageData: Data) -> MessageClassification {
        let b = [UInt8](messageData)
        let top = MIMEHeaders.parse(b, 0, b.count)
        let ct = ContentType(parsing: MIMEHeaders(top.fields)["Content-Type"])
        let proto = ct.parameter("protocol")?.lowercased()
        if ct.mimeType == "multipart/encrypted" && proto == "application/pgp-encrypted" { return .pgpMimeEncrypted }
        if ct.mimeType == "multipart/signed" && proto == "application/pgp-signature" { return .pgpMimeSigned }

        // Nothing PGP-ish at all? Base64/QP text parts could hide armor, so only bail out early
        // when there is no encoded text at all.
        let hasMarker = Bytes.containsCaseInsensitive(b, "-----BEGIN PGP ")
            || Bytes.containsCaseInsensitive(b, "application/pgp")
        if !hasMarker && !Bytes.containsCaseInsensitive(b, "content-transfer-encoding") { return .none }

        let root = MIMEEntity(data: messageData)
        if root.first(where: { $0.isPGPMIMEEncrypted }) != nil { return .pgpMimeEncrypted }
        if root.first(where: { $0.isPGPMIMESigned }) != nil { return .pgpMimeSigned }
        for leaf in root.leaves where isInlineCandidate(leaf) {
            let scan = Armor.scan(leaf.decodedBody)
            if !scan.blocks.isEmpty || scan.truncated { return .inline }
        }
        return .none
    }

    // MARK: - Completeness

    /// Whether the message looks complete enough for gpg: no multipart on the way to a PGP part is missing
    /// its closing boundary, and every armor block has its END line. Mail hands the extension truncated
    /// data for message-list previews. Plain non-PGP messages are complete. Cheap, no gpg.
    public static func isComplete(messageData: Data) -> Bool {
        let b = [UInt8](messageData)
        // Armor can hide in base64/QP text, so only skip when there is no encoded text either.
        guard Bytes.containsCaseInsensitive(b, "-----BEGIN PGP ") || Bytes.containsCaseInsensitive(b, "application/pgp")
            || Bytes.containsCaseInsensitive(b, "content-transfer-encoding") else { return true }
        return isComplete(MIMEEntity(data: messageData))
    }

    static func isComplete(_ e: MIMEEntity) -> Bool {
        if e.isPGPMIMEEncrypted {
            guard e.isTerminated, e.children.count >= 2 else { return false }
            return !Armor.scan(e.children[1].decodedBody, byteLimit: nil, blockLimit: 1).blocks.isEmpty
        }
        if e.isPGPMIMESigned {
            guard e.isTerminated, e.children.count >= 2 else { return false }
            return hasSignatureArmor(e.children[1].decodedBody) && isComplete(e.children[0])
        }
        if e.contentType.isMultipart {
            if !e.isTerminated && e.children.contains(where: isPGPRelevant) { return false }
            return e.children.allSatisfy(isComplete)
        }
        if isInlineCandidate(e) { return !hasUnterminatedArmor(e.decodedBody) }
        return true
    }

    /// Whether the entity is, or contains, a PGP/MIME part or inline armor.
    static func isPGPRelevant(_ e: MIMEEntity) -> Bool {
        e.first { $0.isPGPMIMEEncrypted || $0.isPGPMIMESigned
            || ($0.children.isEmpty && isInlineCandidate($0) && Bytes.containsCaseInsensitive([UInt8]($0.decodedBody), "-----BEGIN PGP ")) } != nil
    }

    /// True when every multipart in the subtree has its closing boundary.
    static func isStructurallyTerminated(_ e: MIMEEntity) -> Bool {
        e.isTerminated && e.children.allSatisfy(isStructurallyTerminated)
    }

    private static func armorLines(_ data: Data) -> [String] {
        let b = [UInt8](data)
        return Bytes.lines(b, 0, b.count).map { s, e, _ in
            var end = e
            while end > s, b[end - 1] == Bytes.sp || b[end - 1] == Bytes.tab || b[end - 1] == Bytes.cr { end -= 1 }
            return Bytes.string(b[s..<end])
        }
    }

    static func hasSignatureArmor(_ data: Data) -> Bool {
        let lines = armorLines(data)
        guard let begin = lines.firstIndex(of: Armor.beginSignature) else { return false }
        return lines[(begin + 1)...].contains(Armor.endSignature)
    }

    /// A BEGIN line (message or signed message) without a complete block, or armor above the scan caps (shown as a
    /// neutral preview, never handed to gpg).
    static func hasUnterminatedArmor(_ data: Data) -> Bool {
        let scan = Armor.scan(data)
        return scan.unterminated || scan.truncated
    }

    /// Whether an inline message contains an encrypted (MESSAGE) armor.
    static func hasInlineEncryptedArmor(_ root: MIMEEntity) -> Bool {
        root.leaves.contains { isInlineCandidate($0) && armorLines($0.decodedBody).contains(Armor.beginMessage) }
    }

    static func isInlineCandidate(_ e: MIMEEntity) -> Bool {
        e.contentType.mimeType == "text/plain" && !e.isAttachment
    }
}
