import Foundation

/// A parsed `[GNUPG:]` status line.
public enum GPGStatus: Sendable, Equatable {
    case sigCreated(type: String, pubkeyAlgo: Int, hashAlgo: Int, sigClass: String, timestamp: String, fingerprint: String)
    case newSig(signerUID: String?)
    case goodSig(keyID: String, userID: String)
    case badSig(keyID: String, userID: String)
    case expSig(keyID: String, userID: String)
    case expKeySig(keyID: String, userID: String)
    case revKeySig(keyID: String, userID: String)
    case errSig(keyID: String, pubkeyAlgo: Int, hashAlgo: Int, sigClass: String, timestamp: String, rc: Int, fingerprint: String?)
    case validSig(fingerprint: String, creationDate: String, timestamp: String, primaryFingerprint: String?)
    case trust(TrustLevel)
    case noPubkey(keyID: String)
    case noSeckey(keyID: String)
    case invRecp(reason: Int, recipient: String)
    case invSgnr(reason: Int, signer: String)
    case encTo(keyID: String, pubkeyAlgo: Int, length: Int)
    case beginDecryption
    case endDecryption
    case decryptionOkay
    case decryptionFailed
    /// DECRYPTION_INFO <mdc_method> <sym_algo> [<aead_algo>]
    case decryptionInfo(mdcMethod: Int, symAlgo: Int, aeadAlgo: Int)
    case pinentryLaunched
    case badPassphrase
    case missingPassphrase
    case error(location: String, code: Int)
    case failure(location: String, code: Int)
    case other(keyword: String, args: [String])
}

public struct GPGStatusLine: Sendable, Equatable {
    public let keyword: String
    public let args: [String]
    public let status: GPGStatus
}

public enum GPGStatusParser {
    public static let prefix = "[GNUPG:] "

    /// Parses all status lines from (possibly mixed) gpg stderr output; non-status lines are ignored.
    public static func parse(_ text: String) -> [GPGStatusLine] {
        text.split(omittingEmptySubsequences: true, whereSeparator: { $0 == "\n" || $0 == "\r\n" })
            .compactMap { parseLine(String($0)) }
    }

    public static func parse(_ data: Data) -> [GPGStatusLine] {
        parse(Bytes.string([UInt8](data)))
    }

    public static func parseLine(_ rawLine: String) -> GPGStatusLine? {
        var line = rawLine
        if line.hasSuffix("\r") { line.removeLast() }
        guard line.hasPrefix(prefix) else { return nil }
        let content = String(line.dropFirst(prefix.count))
        let parts = content.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard let keyword = parts.first, !keyword.isEmpty else { return nil }
        let args = Array(parts.dropFirst())
        func arg(_ i: Int) -> String { i < args.count ? args[i] : "" }
        func int(_ i: Int) -> Int { Int(arg(i)) ?? 0 }
        func rest(_ i: Int) -> String { unescape(args.count > i ? args[i...].joined(separator: " ") : "") }
        func errCode(_ i: Int) -> Int { (Int(arg(i)) ?? 0) & 0xFFFF }

        let status: GPGStatus
        switch keyword {
        case "SIG_CREATED":
            status = .sigCreated(type: arg(0), pubkeyAlgo: int(1), hashAlgo: int(2), sigClass: arg(3), timestamp: arg(4), fingerprint: arg(5))
        case "NEWSIG":
            status = .newSig(signerUID: args.isEmpty ? nil : rest(0))
        case "GOODSIG": status = .goodSig(keyID: arg(0), userID: rest(1))
        case "BADSIG": status = .badSig(keyID: arg(0), userID: rest(1))
        case "EXPSIG": status = .expSig(keyID: arg(0), userID: rest(1))
        case "EXPKEYSIG": status = .expKeySig(keyID: arg(0), userID: rest(1))
        case "REVKEYSIG": status = .revKeySig(keyID: arg(0), userID: rest(1))
        case "ERRSIG":
            let fpr = arg(6)
            status = .errSig(keyID: arg(0), pubkeyAlgo: int(1), hashAlgo: int(2), sigClass: arg(3), timestamp: arg(4),
                             rc: int(5), fingerprint: (fpr.isEmpty || fpr == "-") ? nil : fpr)
        case "VALIDSIG":
            let primary = arg(9)
            status = .validSig(fingerprint: arg(0), creationDate: arg(1), timestamp: arg(2), primaryFingerprint: primary.isEmpty ? nil : primary)
        case "TRUST_UNDEFINED": status = .trust(.undefined)
        case "TRUST_NEVER": status = .trust(.never)
        case "TRUST_MARGINAL": status = .trust(.marginal)
        case "TRUST_FULLY": status = .trust(.fully)
        case "TRUST_ULTIMATE": status = .trust(.ultimate)
        case "NO_PUBKEY": status = .noPubkey(keyID: arg(0))
        case "NO_SECKEY": status = .noSeckey(keyID: arg(0))
        case "INV_RECP": status = .invRecp(reason: int(0), recipient: rest(1))
        case "INV_SGNR": status = .invSgnr(reason: int(0), signer: rest(1))
        case "ENC_TO": status = .encTo(keyID: arg(0), pubkeyAlgo: int(1), length: int(2))
        case "BEGIN_DECRYPTION": status = .beginDecryption
        case "END_DECRYPTION": status = .endDecryption
        case "DECRYPTION_OKAY": status = .decryptionOkay
        case "DECRYPTION_FAILED": status = .decryptionFailed
        case "DECRYPTION_INFO": status = .decryptionInfo(mdcMethod: int(0), symAlgo: int(1), aeadAlgo: int(2))
        case "PINENTRY_LAUNCHED": status = .pinentryLaunched
        case "BAD_PASSPHRASE": status = .badPassphrase
        case "MISSING_PASSPHRASE": status = .missingPassphrase
        case "ERROR": status = .error(location: arg(0), code: errCode(1))
        case "FAILURE": status = .failure(location: arg(0), code: errCode(1))
        default: status = .other(keyword: keyword, args: args)
        }
        return GPGStatusLine(keyword: keyword, args: args, status: status)
    }

    /// Undoes gpg's percent-escaping of free-text status fields.
    static func unescape(_ s: String) -> String {
        guard s.contains("%") else { return s }
        return Bytes.string(ParameterizedHeader.percentDecode(s))
    }

    /// Groups signature-related status lines into per-signature results.
    public static func signatures(from lines: [GPGStatusLine]) -> [SignatureResult] {
        var results: [SignatureResult] = []
        var current: SignatureResult? = nil
        var currentHasStatus = false

        func flush() {
            if let c = current, currentHasStatus { results.append(c) }
            current = nil
            currentHasStatus = false
        }
        func begin(_ status: SignatureStatus, keyID: String, userID: String?) {
            if currentHasStatus { flush() }
            var c = current ?? SignatureResult(status: status)
            c.status = status
            c.keyID = keyID
            if let userID, !userID.isEmpty { c.userID = userID }
            current = c
            currentHasStatus = true
        }

        for l in lines {
            switch l.status {
            case .newSig:
                flush()
                current = SignatureResult(status: .error)
            case let .goodSig(k, u): begin(.good, keyID: k, userID: u)
            case let .badSig(k, u): begin(.bad, keyID: k, userID: u)
            case let .expSig(k, u): begin(.expiredSignature, keyID: k, userID: u)
            case let .expKeySig(k, u): begin(.expiredKey, keyID: k, userID: u)
            case let .revKeySig(k, u): begin(.revokedKey, keyID: k, userID: u)
            case let .errSig(k, _, _, _, ts, rc, fpr):
                begin(rc == 9 ? .noPublicKey : .error, keyID: k, userID: nil)
                current?.errorCode = rc
                current?.fingerprint = fpr
                current?.created = Double(ts).map { Date(timeIntervalSince1970: $0) }
            case let .validSig(fpr, _, ts, primary):
                current?.fingerprint = fpr
                current?.primaryFingerprint = primary
                current?.created = Double(ts).map { Date(timeIntervalSince1970: $0) }
            case let .trust(level):
                current?.trust = level
            default:
                break
            }
        }
        flush()
        return results
    }
}

/// Parser for `gpg --with-colons` key listings.
public enum GPGColonsParser {
    public static func parseKeys(_ text: String) -> [KeyInfo] {
        var keys: [KeyInfo] = []
        var current: KeyInfo? = nil
        var lastWasSubkey = false

        func flush() {
            if let c = current { keys.append(c) }
            current = nil
        }

        for rawLine in text.split(whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            let f = rawLine.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard let type = f.first else { continue }
            func field(_ i: Int) -> String { i < f.count ? f[i] : "" }
            switch type {
            case "pub", "sec":
                flush()
                let caps = field(11)
                current = KeyInfo(
                    fingerprint: "",
                    keyID: field(4),
                    isSecret: type == "sec",
                    validity: field(1),
                    ownerTrust: field(8),
                    algorithm: Int(field(3)) ?? 0,
                    length: Int(field(2)) ?? 0,
                    curve: field(16).isEmpty ? nil : field(16),
                    created: date(field(5)),
                    expires: date(field(6)),
                    capabilities: KeyCapabilities(field: caps, usable: true),
                    isDisabled: caps.contains("D"),
                    userIDs: [],
                    subkeys: []
                )
                lastWasSubkey = false
            case "sub", "ssb":
                guard current != nil else { continue }
                current?.subkeys.append(SubkeyInfo(
                    fingerprint: "",
                    keyID: field(4),
                    validity: field(1),
                    algorithm: Int(field(3)) ?? 0,
                    length: Int(field(2)) ?? 0,
                    created: date(field(5)),
                    expires: date(field(6)),
                    capabilities: KeyCapabilities(field: field(11), usable: false)
                ))
                lastWasSubkey = true
            case "fpr":
                guard current != nil else { continue }
                let fpr = field(9)
                if lastWasSubkey, let idx = current?.subkeys.indices.last {
                    if current?.subkeys[idx].fingerprint.isEmpty == true { current?.subkeys[idx].fingerprint = fpr }
                } else if current?.fingerprint.isEmpty == true {
                    current?.fingerprint = fpr
                }
            case "uid":
                guard current != nil else { continue }
                current?.userIDs.append(UserID(uid: unescape(field(9)), validity: field(1)))
                lastWasSubkey = false
            default:
                continue
            }
        }
        flush()
        return keys
    }

    /// Dates are either seconds since epoch or ISO 8601 basic (YYYYMMDDTHHMMSS).
    static func date(_ s: String) -> Date? {
        if s.isEmpty { return nil }
        if let t = Double(s) { return t == 0 ? nil : Date(timeIntervalSince1970: t) }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss"
        return f.date(from: s)
    }

    /// Undoes `\xHH` escaping used in colons output.
    static func unescape(_ s: String) -> String {
        guard s.contains("\\x") else { return s }
        let u = Array(s.utf8)
        var out: [UInt8] = []
        var i = 0
        while i < u.count {
            if u[i] == 0x5C, i + 3 < u.count, u[i + 1] == 0x78,
               let h = ParameterizedHeader.hexValue(u[i + 2]), let l = ParameterizedHeader.hexValue(u[i + 3]) {
                out.append(h << 4 | l)
                i += 4
            } else {
                out.append(u[i])
                i += 1
            }
        }
        return Bytes.string(out)
    }
}

/// RFC 3156 micalg names for OpenPGP hash algorithm IDs.
public enum Micalg {
    public static func name(forHashAlgorithm id: Int) -> String? {
        switch id {
        case 1: return "pgp-md5"
        case 2: return "pgp-sha1"
        case 3: return "pgp-ripemd160"
        case 8: return "pgp-sha256"
        case 9: return "pgp-sha384"
        case 10: return "pgp-sha512"
        case 11: return "pgp-sha224"
        default: return nil
        }
    }
}
