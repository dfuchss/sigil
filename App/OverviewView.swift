import ServiceManagement
import SwiftUI

/// The health checklist and a short how-to.
struct OverviewView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow
    let goTo: (SidebarItem) -> Void
    @State private var confirmingKeyserver = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                checklist
                howTo
            }
            .padding(24)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .keyserverSetupDialog(isPresented: $confirmingKeyserver)
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("OpenPGP for Apple Mail").font(.title2.bold())
                Text(allGood ? "Everything is set up." : "Some steps are still open.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button { model.showFindKey = true } label: { Label("Find Key…", systemImage: "magnifyingglass") }
            Button { openWindow(id: "help") } label: { Label("Help", systemImage: "questionmark.circle") }
        }
    }

    private var allGood: Bool { checks.allSatisfy { $0.ok == true || $0.warning } }

    private struct Check: Identifiable {
        let id: String
        let title: String
        /// nil: not known yet (shown neutral).
        let ok: Bool?
        let detail: String
        var action: (title: String, run: () -> Void)?
        /// Not ok, but nothing breaks: shown yellow and not counted as an open step.
        var warning = false
    }

    private var checks: [Check] {
        let helperOK = model.helperStatus == .enabled && model.gpgError == nil
        let helperDetail: String
        if model.helperStatus != .enabled {
            helperDetail = HelperAgent.describe(model.helperStatus)
        } else if let error = model.gpgError {
            helperDetail = "Registered, but not answering: \(error)"
        } else {
            helperDetail = "Registered and running."
        }
        let pinentryOK = model.pinentry?.usesPinentryMac == true
        let pinentryDetail: String
        if let error = model.pinentryError {
            pinentryDetail = error
        } else if model.pinentry == nil {
            pinentryDetail = "Not checked yet."
        } else if pinentryOK {
            pinentryDetail = "gpg-agent uses pinentry-mac."
        } else if model.pinentry?.pinentryMacPath != nil {
            pinentryDetail = "gpg-agent does not use pinentry-mac; Mail cannot show a passphrase prompt. Fix it in Settings > Advanced."
        } else {
            pinentryDetail = "pinentry-mac is not installed: brew install pinentry-mac"
        }
        let keyserverURL = model.keyserver?.keyserver
        let keyserverDetail: String
        if let error = model.keyserverError {
            keyserverDetail = error
        } else if model.keyserver == nil {
            keyserverDetail = "Not checked yet."
        } else if let keyserverURL {
            keyserverDetail = keyserverURL
        } else {
            keyserverDetail = "No keyserver configured. Finding and fetching keys only works via WKD."
        }
        let extensionDetail: String
        switch model.mailExtension {
        case .enabled: extensionDetail = "Enabled in Mail."
        case .disabled: extensionDetail = "Not enabled. In Mail, open Mail > Settings > Extensions and tick Sigil."
        case .unknown: extensionDetail = "Could not be determined. Check Mail > Settings > Extensions."
        }
        let secretCount = model.secretKeys.count
        return [
            Check(id: "helper", title: "Helper registered and running", ok: model.hasLoaded ? helperOK : nil,
                  detail: helperDetail, action: helperAction()),
            Check(id: "gpg", title: "GnuPG found", ok: model.hasLoaded ? model.gpgVersion != nil : nil,
                  detail: model.gpgVersion ?? (model.gpgError ?? "Not checked yet."),
                  action: model.gpgVersion == nil ? ("Settings…", { openSettings() }) : nil),
            Check(id: "pinentry", title: "pinentry-mac configured", ok: model.hasLoaded ? pinentryOK : nil,
                  detail: pinentryDetail, action: nil),
            Check(id: "keyserver", title: "Keyserver configured in gpg",
                  ok: model.hasLoaded && model.keyserver != nil ? keyserverURL != nil : nil,
                  detail: keyserverDetail,
                  action: model.keyserver != nil && keyserverURL == nil
                      ? ("Set up keys.openpgp.org…", { confirmingKeyserver = true }) : nil,
                  warning: model.keyserver != nil && keyserverURL == nil),
            Check(id: "extension", title: "Mail extension enabled",
                  ok: model.mailExtension == .unknown ? nil : model.mailExtension == .enabled,
                  detail: extensionDetail, action: ("Open Mail", { AppModel.openMail() })),
            Check(id: "key", title: "A secret key with an email address", ok: model.hasLoaded ? secretCount > 0 : nil,
                  detail: secretCount > 0
                      ? "\(secretCount) secret key\(secretCount == 1 ? "" : "s")."
                      : (model.keysError ?? "Create one with gpg --quick-gen-key \"Name <you@example.org>\"."),
                  action: secretCount > 0 ? ("Show", { goTo(.myKeys) }) : nil),
        ]
    }

    private func helperAction() -> (title: String, run: () -> Void)? {
        switch model.helperStatus {
        case .requiresApproval: return ("Open Login Items", { SMAppService.openSystemSettingsLoginItems() })
        case .enabled: return nil
        default: return ("Register", { Task { await model.register() } })
        }
    }

    private func openSettings() {
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
    }

    private var checklist: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(checks) { check in
                    row(check)
                    if check.id != checks.last?.id { Divider() }
                }
            }
        } label: {
            Text("Health").font(.headline)
        }
    }

    private func row(_ check: Check) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: check.ok == true ? "checkmark.circle.fill"
                  : check.warning ? "exclamationmark.triangle.fill"
                  : check.ok == false ? "xmark.circle.fill" : "circle.dotted")
                .foregroundStyle(check.ok == true ? Color.green : check.warning ? Color.orange
                                 : check.ok == false ? Color.red : Color.secondary)
                .font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(check.title).fontWeight(.medium)
                Text(check.detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Spacer()
            if check.ok != true, let action = check.action {
                Button(action.title, action: action.run)
            }
        }
        .padding(.vertical, 8)
    }

    private var howTo: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Label("Write a message in Mail and use the Sigil buttons to sign or encrypt it.", systemImage: "square.and.pencil")
                Label("Signed messages show Mail's signed badge; encrypted ones open as usual.", systemImage: "checkmark.seal")
                Label("Problems appear as a banner and a red or yellow box at the top of the message.", systemImage: "exclamationmark.triangle")
                Label("Keys of senders you do not know yet are listed under Missing Keys.", systemImage: "questionmark.key.filled")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 4)
        } label: {
            Text("How to use").font(.headline)
        }
    }
}
