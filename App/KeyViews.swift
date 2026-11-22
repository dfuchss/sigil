import SigilCore
import SwiftUI

enum Validity {
    static func describe(_ letter: String) -> String {
        switch letter {
        case "o": return "unknown (new)"
        case "i": return "invalid"
        case "d": return "disabled"
        case "r": return "revoked"
        case "e": return "expired"
        case "-", "q", "": return "unknown"
        case "n": return "not valid"
        case "m": return "marginal"
        case "f": return "full"
        case "u": return "ultimate"
        case "w": return "well known"
        case "s": return "special"
        default: return letter
        }
    }

    static func describe(expiry: Date?) -> String {
        expiry.map { $0.formatted(date: .abbreviated, time: .omitted) } ?? "never"
    }
}

/// A small rounded label such as "Preferred" or "Expired".
struct Badge: View {
    let text: String
    var color: Color = .secondary

    init(_ text: String, color: Color = .secondary) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.25), in: Capsule())
            .foregroundStyle(.primary)
    }
}

struct KeyRow: View {
    @EnvironmentObject private var model: AppModel
    let key: KeyInfo
    var showPreference = false

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(key.userIDs, id: \.uid) { userID in
                HStack(spacing: 6) {
                    Text(userID.uid).fontWeight(.medium)
                    Text("(\(Validity.describe(userID.validity)))").foregroundStyle(.secondary)
                    if showPreference, let email = userID.email, model.preferredFingerprint(for: email) == key.fingerprint.uppercased() {
                        Badge("Preferred", color: .accentColor)
                    }
                }
            }
            Text(Fingerprint.grouped(key.fingerprint))
                .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            Text("Validity: \(Validity.describe(key.validity)) · Expires: \(Validity.describe(expiry: key.expires))"
                 + (key.isDisabled ? " · disabled" : ""))
                .font(.caption).foregroundStyle(.secondary)
            if showPreference { preferenceButtons }
        }
        .padding(.vertical, 4)
        .contextMenu { preferenceButtons }
    }

    /// "Prefer for <email>" only when that address has more than one usable key.
    @ViewBuilder private var preferenceButtons: some View {
        let emails = key.userIDs.compactMap(\.email)
        ForEach(emails, id: \.self) { email in
            if model.usableKeyCount(for: email) > 1, RecipientKeyChoice.isUsableEncryptionKey(key, for: email) {
                if model.preferredFingerprint(for: email) == key.fingerprint.uppercased() {
                    Button("Clear preference for \(email)") { Task { await model.setPreferred(email: email, fingerprint: nil) } }
                        .buttonStyle(.link).font(.caption)
                } else {
                    Button("Prefer for \(email)") { Task { await model.setPreferred(email: email, fingerprint: key.fingerprint) } }
                        .buttonStyle(.link).font(.caption)
                }
            }
        }
    }
}

private struct KeysUnavailable: View {
    let error: String?
    let loaded: Bool

    var body: some View {
        if let error {
            ContentUnavailableView("Keys unavailable", systemImage: "exclamationmark.triangle", description: Text(error))
        } else if loaded {
            ContentUnavailableView("No keys", systemImage: "key")
        } else {
            ProgressView()
        }
    }
}

/// Secret keys with an email address.
struct MyKeysView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if model.secretKeys.isEmpty {
            KeysUnavailable(error: model.keysError, loaded: model.hasLoaded)
        } else {
            List(model.secretKeys, id: \.fingerprint) { KeyRow(key: $0) }
        }
    }
}

/// Public keys with a search field; with several keys for one address, one can be preferred for encryption.
struct PublicKeysView: View {
    @EnvironmentObject private var model: AppModel
    @State private var query = ""

    private var filtered: [KeyInfo] {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return model.publicKeys }
        let hex = needle.filter { !$0.isWhitespace }
        return model.publicKeys.filter { key in
            key.userIDs.contains { $0.uid.lowercased().contains(needle) }
                || key.fingerprint.lowercased().contains(hex) || key.keyID.lowercased().contains(hex)
        }
    }

    var body: some View {
        Group {
            if model.publicKeys.isEmpty {
                KeysUnavailable(error: model.keysError, loaded: model.hasLoaded)
            } else if filtered.isEmpty {
                ContentUnavailableView.search(text: query)
            } else {
                VStack(spacing: 0) {
                    if let error = model.preferredError {
                        Text(error).font(.caption).foregroundStyle(.red).padding(8)
                    }
                    List(filtered, id: \.fingerprint) { KeyRow(key: $0, showPreference: true) }
                }
            }
        }
        .searchable(text: $query, prompt: "Name, email or fingerprint")
    }
}
