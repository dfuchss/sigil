import AppKit
import os
import ServiceManagement
import SigilCore
import SwiftUI

/// State shared by the main window, the settings and the About window: helper, gpg, keys, pinentry and the Mail
/// extension.
@MainActor
final class AppModel: ObservableObject {
    enum ExtensionState { case enabled, disabled, unknown }

    @Published var helperStatus: SMAppService.Status = HelperAgent.service.status
    @Published var helperMessage: String?
    /// The first line of `gpg --version`; nil when the helper or gpg is not available.
    @Published var gpgVersion: String?
    @Published var gpgError: String?
    /// The helper's gpg path setting (stored by the helper, not in the App Group).
    @Published var gpgPathSetting: GPGPathStatus?
    @Published var gpgPathError: String?
    @Published var secretKeys: [KeyInfo] = []
    @Published var publicKeys: [KeyInfo] = []
    @Published var keysError: String?
    @Published var pinentry: PinentryStatus?
    @Published var pinentryError: String?
    @Published var keyserver: KeyserverStatus?
    @Published var keyserverError: String?
    @Published var mailExtension: ExtensionState = .unknown
    @Published var preferredKeys: [PreferredKeyEntry] = []
    @Published var preferredError: String?
    @Published var isRefreshing = false
    @Published var hasLoaded = false
    /// Presents the Find Key sheet in the main window.
    @Published var showFindKey = false

    private let logger = Logger(subsystem: "org.fuchss.sigil", category: "app")
    private let client = HelperClient.shared

    /// "2.4.5" from "gpg (GnuPG) 2.4.5".
    var gpgVersionNumber: String? { gpgVersion?.split(separator: " ").last.map(String.init) }


    func refresh() async {
        isRefreshing = true
        defer { isRefreshing = false; hasLoaded = true }
        #if DEBUG
        if DebugLaunch.demo {
            helperStatus = .enabled
            mailExtension = .enabled
            gpgVersion = DemoData.gpgVersion
            secretKeys = DemoData.secretKeys
            publicKeys = DemoData.publicKeys
            pinentry = DemoData.pinentry
            keyserver = DemoData.keyserver
            if preferredKeys.isEmpty { preferredKeys = DemoData.preferredKeys }
            return
        }
        #endif
        helperStatus = HelperAgent.service.status
        mailExtension = await Task.detached { Self.queryMailExtension() }.value
        do {
            gpgVersion = try await client.ping()
            gpgError = nil
        } catch {
            gpgVersion = nil
            gpgError = error.localizedDescription
            logger.error("ping failed: \(error.localizedDescription, privacy: .private)")
        }
        do {
            secretKeys = try await client.listKeys(secret: true)
            publicKeys = try await client.listKeys(secret: false)
            keysError = nil
        } catch {
            keysError = error.localizedDescription
            logger.error("listKeys failed: \(error.localizedDescription, privacy: .private)")
        }
        do {
            pinentry = try await client.pinentryStatus()
            pinentryError = nil
        } catch {
            pinentry = nil
            pinentryError = error.localizedDescription
        }
        do {
            keyserver = try await client.keyserverStatus()
            keyserverError = nil
        } catch {
            keyserver = nil
            keyserverError = error.localizedDescription
        }
        do {
            preferredKeys = try await client.listPreferredKeys()
            preferredError = nil
        } catch {
            preferredError = error.localizedDescription
        }
        gpgPathSetting = try? await client.gpgPathStatus()
    }

    func register() async {
        do {
            try HelperAgent.service.register()
            helperMessage = nil
        } catch {
            helperMessage = "Registration failed: \(error.localizedDescription)"
        }
        await refresh()
    }

    func unregister() async {
        do {
            try await HelperAgent.service.unregister()
            helperMessage = nil
        } catch {
            helperMessage = "Unregistration failed: \(error.localizedDescription)"
        }
        await refresh()
    }

    func fixPinentry() async {
        do {
            pinentry = try await client.fixPinentry()
            pinentryError = nil
            logger.info("pinentry fixed")
        } catch {
            pinentryError = error.localizedDescription
            logger.error("pinentry fix failed: \(error.localizedDescription, privacy: .private)")
        }
    }

    func fixKeyserver() async {
        do {
            keyserver = try await client.fixKeyserver()
            keyserverError = nil
            logger.info("keyserver configured")
        } catch {
            keyserverError = error.localizedDescription
            logger.error("keyserver fix failed: \(error.localizedDescription, privacy: .private)")
        }
    }

    /// Has the helper validate and store the gpg path override (empty clears it), then reconnects so it applies at
    /// once. The helper refuses paths it does not trust (see `GPGPathValidator`).
    func applyGPGPath(_ path: String) async {
        #if DEBUG
        if DebugLaunch.demo { return }
        #endif
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            gpgPathSetting = try await client.setGPGPath(trimmed.isEmpty ? nil : (trimmed as NSString).expandingTildeInPath)
            gpgPathError = nil
        } catch {
            gpgPathError = error.localizedDescription
            logger.error("setting the gpg path failed: \(error.localizedDescription, privacy: .private)")
        }
        client.reconnect()
        await refresh()
    }

    // MARK: Preferred keys

    /// The fingerprint preferred for an address, if the preference is still usable.
    func preferredFingerprint(for email: String) -> String? {
        preferredKeys.first { $0.email == email.lowercased() && $0.usable }?.fingerprint
    }

    /// Usable encryption keys that carry this address; "Prefer" is only offered when there are several.
    func usableKeyCount(for email: String) -> Int {
        publicKeys.filter { RecipientKeyChoice.isUsableEncryptionKey($0, for: email) }.count
    }

    func setPreferred(email: String, fingerprint: String?) async {
        #if DEBUG
        if DebugLaunch.demo { return }
        #endif
                do {
            preferredKeys = try await client.setPreferredKey(email: email, fingerprint: fingerprint)
            preferredError = nil
        } catch {
            preferredError = error.localizedDescription
        }
    }

    // MARK: Mail

    /// Whether Mail uses the extension, from `pluginkit` ("+" = enabled, "-" = disabled). The app is not sandboxed.
    nonisolated static func queryMailExtension() -> ExtensionState {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pluginkit")
        process.arguments = ["-mAD", "-p", "com.apple.email.extension", "-i", "\(SigilXPC.bundlePrefix ?? "org.fuchss.sigil").extension"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return .unknown }
        let data = (try? pipe.fileHandleForReading.readToEnd()) ?? Data()
        process.waitUntilExit()
        let line = String(decoding: data, as: UTF8.self).split(separator: "\n").first.map(String.init) ?? ""
        switch line.first {
        case "+": return .enabled
        case "-": return .disabled
        default: return line.isEmpty ? .disabled : .unknown
        }
    }

    static func openMail() {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.mail") else { return }
        NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
    }
}
