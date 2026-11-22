import Foundation
import Security

@objc public protocol GPGServiceProtocol {
    func ping(reply: @escaping (String) -> Void)                     // returns gpg version string or error text
    func listKeys(secret: Bool, reply: @escaping (Data?, String?) -> Void)          // JSON [KeyInfo], error
    func encodingStatus(from: String, recipients: [String], reply: @escaping (Data?, String?) -> Void) // JSON EncodingStatus {canSign, canEncrypt, signerFingerprint?, missingRecipients[], unverifiedRecipients[]}
    func encode(message: Data, sign: Bool, encrypt: Bool, from: String, recipients: [String], hiddenRecipients: [String], reply: @escaping (Data?, String?) -> Void) // full RFC822 out
    func decode(message: Data, interactive: Bool, allowMixed: Bool, reply: @escaping (Data?, String?) -> Void) // JSON DecodeOutcome (decoded message base64 inside), nil+nil = not PGP; interactive false = never prompt for a passphrase; allowMixed = the user asked to decrypt encrypted parts mixed with other content (never splice that plaintext into a message Mail renders)
    func pinentryStatus(reply: @escaping (Data?, String?) -> Void)                  // JSON PinentryStatus
    func fixPinentry(reply: @escaping (Data?, String?) -> Void)                     // points pinentry-program at pinentry-mac; JSON PinentryStatus after the fix
    func keyserverStatus(reply: @escaping (Data?, String?) -> Void)                 // JSON KeyserverStatus
    func fixKeyserver(reply: @escaping (Data?, String?) -> Void)                    // appends `keyserver hkps://keys.openpgp.org` to dirmngr.conf (the helper picks the value); JSON KeyserverStatus after the fix
    func listMissingKeys(reply: @escaping (Data?, String?) -> Void)                 // JSON [MissingKeyEntry], dismissed ones included
    func dismissMissingKey(id: String, reply: @escaping (Data?, String?) -> Void)   // JSON [MissingKeyEntry] after the change
    func restoreMissingKey(id: String, reply: @escaping (Data?, String?) -> Void)   // JSON [MissingKeyEntry] after the change
    func removeMissingKey(id: String, reply: @escaping (Data?, String?) -> Void)    // dismissed entries only; JSON [MissingKeyEntry] after the change
    func removeDismissedMissingKeys(reply: @escaping (Int, String?) -> Void)        // number of entries removed
    func searchMissingKey(id: String, reply: @escaping (Data?, String?) -> Void)    // JSON KeySearchResult (candidates found in a temporary GnuPG home; the real keyring is untouched)
    func searchKeys(query: String, reply: @escaping (Data?, String?) -> Void)       // manual "Find Key": query is an email, a fingerprint or a 16-digit key ID; same JSON KeySearchResult and token flow
    func importCandidateKey(token: String, fingerprint: String, reply: @escaping (Data?, String?) -> Void) // JSON KeyImportResult; the entry is removed only if the key matches the signature
    func listPreferredKeys(reply: @escaping (Data?, String?) -> Void)               // JSON [PreferredKeyEntry] (usable == false: ignored because the key is no longer usable)
    func setPreferredKey(email: String, fingerprint: String?, reply: @escaping (Data?, String?) -> Void) // nil fingerprint clears; JSON [PreferredKeyEntry] after the change
    func discardKeySearch(token: String, reply: @escaping (Data?, String?) -> Void) // deletes the temporary home
    func setGPGPath(_ path: String?, reply: @escaping (Data?, String?) -> Void)    // app only; validated, stored in the helper's own settings (nil/empty = automatic); JSON GPGPathStatus
    func gpgPathStatus(reply: @escaping (Data?, String?) -> Void)                  // app only; JSON GPGPathStatus
}
// Access: the Mail extension may call ping, listKeys, encodingStatus, encode and decode; everything else is app only
// (`ServiceAuthorization`).

/// Names derived from the build's bundle prefix (`org.fuchss.sigil` for Release, `org.fuchss.sigil.dev` for Debug),
/// so a development build never clashes with the installed release copy.
public enum SigilXPC {
    public static func helperBundleID(prefix: String) -> String { "\(prefix).helper" }
    public static func machServiceName(teamID: String, prefix: String) -> String { "\(teamID).\(prefix).helper" }
    public static func appGroupID(teamID: String, prefix: String) -> String { "\(teamID).\(prefix)" }

    /// Code signing requirement for XPC clients: same team, and exactly `<prefix>` or `<prefix>.extension`.
    public static func clientRequirement(teamID: String, prefix: String) -> String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
            + " and (identifier \"\(prefix)\" or identifier \"\(prefix).extension\")"
    }

    /// A value from the bundle's Info.plist, or nil if it is missing, empty or an unexpanded `$(...)`.
    public static func infoValue(_ key: String, bundle: Bundle = .main) -> String? {
        guard let value = bundle.object(forInfoDictionaryKey: key) as? String,
              !value.isEmpty, !value.contains("$(") else { return nil }
        return value
    }

    /// Info.plist keys, all expanded from `SIGIL_BUNDLE_PREFIX` at build time.
    public static var bundlePrefix: String? { infoValue("SigilBundlePrefix") }
    public static var appGroup: String? { infoValue("SigilAppGroup") }
    public static var machService: String? { infoValue("SigilMachServiceName") }
    public static var helperPlistName: String? { infoValue("SigilHelperPlistName") }

    /// Code signing requirement the app and the extension apply to the helper: exactly `<prefix>.helper`, same team.
    public static func helperRequirement(teamID: String, prefix: String) -> String {
        "identifier \"\(helperBundleID(prefix: prefix))\" and anchor apple generic"
            + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// The team identifier from the calling process's own code signature (nil when unsigned or ad hoc).
    public static func ownTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess,
              let signingInformation = information as? [String: Any] else { return nil }
        return signingInformation[kSecCodeInfoTeamIdentifier as String] as? String
    }

    /// The signing identifier of the process behind an XPC audit token, after checking its signature is valid and
    /// satisfies `requirement`; nil otherwise.
    public static func signingIdentifier(auditToken: Data, requirement: String) -> String? {
        let attributes = [kSecGuestAttributeAudit: auditToken] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else { return nil }
        var parsedRequirement: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &parsedRequirement) == errSecSuccess,
              let parsedRequirement,
              SecCodeCheckValidity(code, [], parsedRequirement) == errSecSuccess else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess,
              let signingInformation = information as? [String: Any] else { return nil }
        return signingInformation[kSecCodeInfoIdentifier as String] as? String
    }

    /// Convenience: the XPC interface for `GPGServiceProtocol`.
    public static func makeInterface() -> NSXPCInterface {
        NSXPCInterface(with: GPGServiceProtocol.self)
    }
}
