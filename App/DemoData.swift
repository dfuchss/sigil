#if DEBUG
import CryptoKit
import Foundation
import SigilCore

/// Fixed, made-up data for the README screenshots (`--demo`). Nothing here is read from the helper or the keyring.
enum DemoData {
    static let token = "demo-search"

    /// A plausible but fake fingerprint: the first 20 bytes of SHA-256 over the seed.
    static func fingerprint(_ seed: String) -> String {
        SHA256.hash(data: Data(seed.utf8)).prefix(20).map { String(format: "%02X", $0) }.joined()
    }

    private static func date(_ year: Int, _ month: Int, _ day: Int) -> Date {
        DateComponents(calendar: Calendar(identifier: .gregorian), timeZone: TimeZone(identifier: "UTC"),
                       year: year, month: month, day: day, hour: 12).date!
    }

    private static func key(_ uid: String, secret: Bool, validity: String, trust: String, created: Date, expires: Date?) -> KeyInfo {
        let fp = fingerprint(uid)
        let caps = ["sign": true, "encrypt": true, "certify": true, "authenticate": false]
        var json: [String: Any] = [
            "fingerprint": fp, "keyID": String(fp.suffix(16)), "isSecret": secret, "validity": validity,
            "ownerTrust": trust, "algorithm": 22, "length": 255, "curve": "ed25519",
            "created": created.timeIntervalSince1970, "capabilities": caps, "isDisabled": false,
            "userIDs": [], "subkeys": [],
        ]
        if let expires { json["expires"] = expires.timeIntervalSince1970 }
        let data = try! JSONSerialization.data(withJSONObject: json)
        var info = try! JSONDecoder.sigil.decode(KeyInfo.self, from: data)
        info.userIDs = [UserID(uid: uid, validity: validity)]
        return info
    }

    static let secretKeys = [
        key("Alice Example <alice@example.org>", secret: true, validity: "u", trust: "u", created: date(2024, 3, 14), expires: nil),
    ]

    static let publicKeys = [
        secretKeys[0].asPublic,
        key("Bob Sample <bob@example.net>", secret: false, validity: "f", trust: "f", created: date(2023, 9, 2), expires: date(2028, 9, 1)),
        key("Erin Demo <erin@example.org>", secret: false, validity: "q", trust: "-", created: date(2025, 1, 20), expires: nil),
        key("Frank Test <frank@example.net>", secret: false, validity: "m", trust: "m", created: date(2024, 6, 5), expires: date(2027, 6, 5)),
        key("Grace Old <grace@example.org>", secret: false, validity: "e", trust: "f", created: date(2020, 2, 10), expires: date(2023, 2, 10)),
    ]

    static let preferredKeys = [
        PreferredKeyEntry(email: "bob@example.net", fingerprint: fingerprint("Bob Sample <bob@example.net>"), usable: true),
    ]

    static let gpgVersion = "gpg (GnuPG) 2.5.8"
    static let pinentry = PinentryStatus(
        configPath: "/Users/alice/.gnupg/gpg-agent.conf",
        pinentryProgram: "/opt/homebrew/bin/pinentry-mac", usesPinentryMac: true,
        pinentryMacPath: "/opt/homebrew/bin/pinentry-mac")
    static let keyserver = KeyserverStatus(configPath: "/Users/alice/.gnupg/dirmngr.conf", keyserver: "hkps://keys.openpgp.org")

    static func missingKeys() -> [MissingKeyEntry] {
        let now = Date()
        return [
            MissingKeyEntry(keyID: String(fingerprint("bob-signing").suffix(16)), fingerprint: nil, senderEmail: "bob@example.net",
                            signerUserID: nil, firstSeen: now.addingTimeInterval(-6 * 86400), lastSeen: now.addingTimeInterval(-3600),
                            count: 3, dismissed: false),
            MissingKeyEntry(keyID: String(fingerprint("carol-signing").suffix(16)), fingerprint: nil, senderEmail: "carol@example.com",
                            signerUserID: nil, firstSeen: now.addingTimeInterval(-2 * 86400), lastSeen: now.addingTimeInterval(-2 * 86400),
                            count: 1, dismissed: false),
        ]
    }

    /// The Find Key result for dave@example.org: WKD hit, keyserver hit, expired keyserver hit.
    static func search(email: String) -> KeySearchResult {
        func candidate(_ seed: String, created: Date, expired: Bool, source: String) -> KeyCandidate {
            let fp = fingerprint(seed)
            return KeyCandidate(fingerprint: fp, keyID: String(fp.suffix(16)),
                                userIDs: [.init(uid: "Dave Example <\(email)>")], created: created, expired: expired,
                                revoked: false, sources: [source], matchesSignature: false)
        }
        return KeySearchResult(token: token, candidates: [
            candidate("dave-wkd", created: date(2025, 2, 11), expired: false, source: "auto-key-locate"),
            candidate("dave-keyserver", created: date(2024, 11, 3), expired: false, source: "keyserver"),
            candidate("dave-old", created: date(2019, 5, 17), expired: true, source: "keyserver"),
        ], message: nil)
    }
}

private extension KeyInfo {
    var asPublic: KeyInfo { var copy = self; copy.isSecret = false; return copy }
}

private extension JSONDecoder {
    static var sigil: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .secondsSince1970; return d }
}
#endif
