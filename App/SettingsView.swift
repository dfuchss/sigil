import ServiceManagement
import SigilCore
import SwiftUI

/// The Settings scene (Cmd+,): General (gpg path, helper) and Advanced (pinentry).
struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem { Label("General", systemImage: "gearshape") }
            AdvancedSettingsView()
                .tabItem { Label("Advanced", systemImage: "wrench.and.screwdriver") }
        }
        .frame(width: 520, height: 520)
    }
}

struct GeneralSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var gpgPath = ""

    var body: some View {
        Form {
            Section("GnuPG") {
                TextField("gpg path", text: $gpgPath, prompt: Text("Automatic (Homebrew)"))
                    .onSubmit { Task { await model.applyGPGPath(gpgPath) } }
                HStack {
                    Text(model.gpgVersion ?? model.gpgError ?? "…")
                        .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    Spacer()
                    Button("Apply") { Task { await model.applyGPGPath(gpgPath) } }
                }
                if let error = model.gpgPathError { Text(error).font(.caption).foregroundStyle(.red) }
                Text("Leave empty to use /opt/homebrew/bin/gpg or /usr/local/bin/gpg. The helper only accepts a gpg "
                     + "owned by you or root that nobody else can modify, outside temporary folders; otherwise it "
                     + "falls back to those.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Helper") {
                LabeledContent("Status", value: HelperAgent.describe(model.helperStatus))
                if let message = model.helperMessage { Text(message).foregroundStyle(.red) }
                HStack {
                    Button("Register") { Task { await model.register() } }
                    Button("Unregister") { Task { await model.unregister() } }
                    if model.helperStatus == .requiresApproval {
                        Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .task {
            await model.refresh()
            gpgPath = model.gpgPathSetting?.configuredPath ?? ""
        }
    }
}

struct AdvancedSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var confirmingFix = false
    @State private var confirmingKeyserver = false

    var body: some View {
        Form {
            Section("Passphrase prompt (pinentry)") {
                if let error = model.pinentryError {
                    Text(error).foregroundStyle(.red)
                } else if let pinentry = model.pinentry {
                    LabeledContent("pinentry-program", value: pinentry.pinentryProgram ?? "not set (gpg-agent default)")
                        .textSelection(.enabled)
                    LabeledContent("Config file", value: pinentry.configPath).textSelection(.enabled)
                    if pinentry.usesPinentryMac {
                        Label("Uses pinentry-mac", systemImage: "checkmark.circle").foregroundStyle(.green)
                    } else if let pinentryMac = pinentry.pinentryMacPath {
                        Label("Not pinentry-mac: Mail cannot show a passphrase prompt", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                        Button("Fix…") { confirmingFix = true }
                            .confirmationDialog("Set pinentry-program to \(pinentryMac)?", isPresented: $confirmingFix) {
                                Button("Change gpg-agent.conf") { Task { await model.fixPinentry() } }
                                Button("Cancel", role: .cancel) {}
                            } message: {
                                Text("Sigil comments out the current pinentry-program line in \(pinentry.configPath), "
                                     + "adds one for pinentry-mac and reloads gpg-agent.")
                            }
                    } else {
                        Label("pinentry-mac is not installed (brew install pinentry-mac)", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                } else {
                    Text("…")
                }
            }
            Section("Keyserver (dirmngr)") {
                if let error = model.keyserverError {
                    Text(error).foregroundStyle(.red)
                } else if let keyserver = model.keyserver {
                    LabeledContent("keyserver", value: keyserver.keyserver ?? "not set").textSelection(.enabled)
                    LabeledContent("Config file", value: keyserver.configPath).textSelection(.enabled)
                    if keyserver.isConfigured {
                        Label("A keyserver is configured", systemImage: "checkmark.circle").foregroundStyle(.green)
                    } else {
                        Label("No keyserver configured. Finding and fetching keys only works via WKD.",
                              systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                        Button("Set up keys.openpgp.org…") { confirmingKeyserver = true }
                    }
                } else {
                    Text("…")
                }
            }
        }
        .keyserverSetupDialog(isPresented: $confirmingKeyserver)
        .formStyle(.grouped)
        .task { await model.refresh() }
    }
}
