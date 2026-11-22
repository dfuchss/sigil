import Foundation

/// Builds MIME entities (always CRLF line endings).
public enum MIMEBuilder {
    private static let boundaryChars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

    /// A random boundary that cannot appear in quoted-printable or base64 content ("=" is never emitted
    /// unescaped and "_" / "." are not base64 characters, the prefix makes collisions with text very unlikely).
    public static func randomBoundary() -> String {
        var rng = SystemRandomNumberGenerator()
        let suffix = String((0..<28).map { _ in boundaryChars.randomElement(using: &rng)! })
        return "sigil_=_\(suffix)"
    }

    /// Picks a random boundary that does not occur in any of `contents`.
    public static func boundary(notIn contents: [Data]) -> String {
        while true {
            let b = randomBoundary()
            let needle = Data(b.utf8)
            if !contents.contains(where: { $0.range(of: needle) != nil }) { return b }
        }
    }

    /// Serializes an entity from header (name, value) pairs and a body.
    public static func entity(headers: [(String, String)], body: Data) -> Data {
        var out = Data()
        for (name, value) in headers { out.append(Data("\(name): \(value)\r\n".utf8)) }
        out.append(Data(Bytes.crlf))
        out.append(body)
        return out
    }

    /// Builds a multipart body (delimiters + parts + close delimiter) for the given boundary.
    public static func multipartBody(parts: [Data], boundary: String, preamble: String? = nil) -> Data {
        var out = Data()
        if let preamble { out.append(Data("\(preamble)\r\n".utf8)) }
        for p in parts {
            out.append(Data("--\(boundary)\r\n".utf8))
            out.append(p)
            out.append(Data("\r\n".utf8))
        }
        out.append(Data("--\(boundary)--\r\n".utf8))
        return out
    }

    /// RFC 3156 section 5: `multipart/signed` whose first part is exactly `signedEntity`.
    public static func multipartSigned(signedEntity: Data, signature: Data, micalg: String, boundary: String? = nil) -> Data {
        let sigPart = entity(
            headers: [
                ("Content-Type", "application/pgp-signature; name=\"signature.asc\""),
                ("Content-Description", "OpenPGP digital signature"),
                ("Content-Disposition", "attachment; filename=\"signature.asc\""),
            ],
            body: LineEndings.toCRLF(signature)
        )
        let b = boundary ?? self.boundary(notIn: [signedEntity, sigPart])
        let body = multipartBody(
            parts: [signedEntity, sigPart], boundary: b,
            preamble: "This is an OpenPGP/MIME signed message (RFC 4880 and 3156)"
        )
        return entity(
            headers: [("Content-Type", "multipart/signed; micalg=\(micalg);\r\n protocol=\"application/pgp-signature\";\r\n boundary=\"\(b)\"")],
            body: body
        )
    }

    /// RFC 3156 section 4: `multipart/encrypted` with the version part and the ciphertext part.
    public static func multipartEncrypted(armoredCiphertext: Data, boundary: String? = nil) -> Data {
        let versionPart = entity(
            headers: [
                ("Content-Type", "application/pgp-encrypted"),
                ("Content-Description", "PGP/MIME version identification"),
            ],
            body: Data("Version: 1\r\n".utf8)
        )
        let dataPart = entity(
            headers: [
                ("Content-Type", "application/octet-stream; name=\"encrypted.asc\""),
                ("Content-Description", "OpenPGP encrypted message"),
                ("Content-Disposition", "inline; filename=\"encrypted.asc\""),
            ],
            body: LineEndings.toCRLF(armoredCiphertext)
        )
        let b = boundary ?? self.boundary(notIn: [dataPart])
        let body = multipartBody(
            parts: [versionPart, dataPart], boundary: b,
            preamble: "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)"
        )
        return entity(
            headers: [("Content-Type", "multipart/encrypted;\r\n protocol=\"application/pgp-encrypted\";\r\n boundary=\"\(b)\"")],
            body: body
        )
    }
}
