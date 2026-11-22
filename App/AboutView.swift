import AppKit
import SwiftUI

/// Replacement for the standard About panel.
struct AboutView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingLicense = false

    private var name: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? "Sigil" }
    private var version: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?" }
    private var build: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?" }

    var body: some View {
        VStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable().frame(width: 96, height: 96)
            Text(name).font(.title.bold())
            Text("Version \(version) (\(build))").foregroundStyle(.secondary)
            Text("OpenPGP signing and encryption for Apple Mail, using your own GnuPG.")
                .multilineTextAlignment(.center).padding(.top, 4)
            Divider().padding(.vertical, 6)
            Text("\u{00A9} 2026 Dominik Fuchß").font(.callout)
            Text("Licensed under the GNU General Public License v3.0 or later")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("View License…") { showingLicense = true }
            Divider().padding(.vertical, 6)
            VStack(spacing: 2) {
                Text("Uses GnuPG \(model.gpgVersionNumber ?? "(not available)")")
                Text("Not affiliated with Apple or the GnuPG project.")
            }
            .font(.caption).foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(width: 360)
        .task { if model.gpgVersion == nil { await model.refresh() } }
        .sheet(isPresented: $showingLicense) { LicenseView() }
    }
}

/// The GPL text bundled as the `LICENSE` resource.
struct LicenseView: View {
    @Environment(\.dismiss) private var dismiss

    private var text: String {
        guard let url = Bundle.main.url(forResource: "LICENSE", withExtension: nil),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return "The license text is missing from the app bundle. See https://www.gnu.org/licenses/gpl-3.0.txt"
        }
        return text
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                Text(text)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            Divider()
            HStack {
                Spacer()
                Button("Close") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(10)
        }
        .frame(width: 600, height: 480)
    }
}
