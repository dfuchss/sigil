import Foundation

/// Who is on the other end of a helper connection, from the signing identifier of its code signature.
public enum XPCCaller: String, Sendable {
    /// The Sigil app (`<prefix>`).
    case app
    /// The Mail extension (`<prefix>.extension`): it processes untrusted mail, so it gets only what it needs.
    case mailExtension

    /// The caller for a signing identifier, nil for anything else.
    public static func from(signingIdentifier: String, prefix: String) -> XPCCaller? {
        switch signingIdentifier {
        case prefix: return .app
        case "\(prefix).extension": return .mailExtension
        default: return nil
        }
    }
}

/// The methods of `GPGServiceProtocol`.
public enum ServiceMethod: String, CaseIterable, Sendable {
    case ping, listKeys, encodingStatus, encode, decode
    case pinentryStatus, fixPinentry, keyserverStatus, fixKeyserver
    case listMissingKeys, dismissMissingKey, restoreMissingKey, removeMissingKey, removeDismissedMissingKeys
    case searchMissingKey, searchKeys, importCandidateKey, discardKeySearch
    case listPreferredKeys, setPreferredKey
    case setGPGPath, gpgPathStatus
}

/// Which caller may use which method: the Mail extension only reads keys and encodes/decodes messages; everything
/// that changes state or configuration (and the app's own views) is for the app.
public enum ServiceAuthorization {
    public static let extensionMethods: Set<ServiceMethod> = [.ping, .listKeys, .encodingStatus, .encode, .decode]

    public static func isAllowed(_ method: ServiceMethod, for caller: XPCCaller) -> Bool {
        switch caller {
        case .app: return true
        case .mailExtension: return extensionMethods.contains(method)
        }
    }
}

/// The gpg path setting as the app shows it.
public struct GPGPathStatus: Codable, Sendable, Equatable {
    /// The stored override; nil means automatic.
    public var configuredPath: String?
    /// The gpg this connection's service uses.
    public var activePath: String?

    public init(configuredPath: String?, activePath: String?) {
        self.configuredPath = configuredPath
        self.activePath = activePath
    }
}

/// The helper's own settings, in `~/Library/Application Support/<prefix>.helper/settings.json`: outside the App
/// Group container, so the sandboxed Mail extension cannot change them. Only the helper writes them (`setGPGPath`
/// through XPC, app only).
public final class HelperSettings: @unchecked Sendable {
    public let fileURL: URL
    private let lock = NSLock()

    private struct Stored: Codable {
        var gpgPath: String?
    }

    public init(fileURL: URL) {
        self.fileURL = fileURL
    }

    public static func standard(prefix: String) -> HelperSettings {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return HelperSettings(fileURL: base.appendingPathComponent(SigilXPC.helperBundleID(prefix: prefix))
            .appendingPathComponent("settings.json"))
    }

    public func gpgPath() -> String? {
        lock.lock(); defer { lock.unlock() }
        return read().gpgPath
    }

    public func setGPGPath(_ path: String?) throws {
        lock.lock(); defer { lock.unlock() }
        var stored = read()
        stored.gpgPath = path
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try SafeFile.write(try JSONEncoder().encode(stored), to: fileURL)
    }

    private func read() -> Stored {
        guard let data = try? SafeFile.read(fileURL) else { return Stored() }
        return (try? JSONDecoder().decode(Stored.self, from: data)) ?? Stored()
    }
}
