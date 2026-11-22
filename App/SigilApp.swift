import SwiftUI

@main
struct SigilApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.openWindow) private var openWindow

    init() {
        // Hidden switch for headless setups and testing: `open Sigil.app --args --register-helper`.
        if CommandLine.arguments.contains("--unregister-helper") {
            HelperAgent.unregisterAndLog()
        }
        if CommandLine.arguments.contains("--register-helper") {
            HelperAgent.registerAndLog()
        }
        HelperAgent.removeLegacyGPGPath()
        #if DEBUG
        // Test switch: `Sigil.app/Contents/MacOS/Sigil --decode-file a.eml b.eml` prints decode summaries and exits.
        if let index = CommandLine.arguments.firstIndex(of: "--decode-file") {
            DecodeFileCommand.run(paths: Array(CommandLine.arguments[(index + 1)...]))
        }
        // Test switch: `Sigil.app/Contents/MacOS/Sigil --encode-file in.eml out.eml [--sign] [--encrypt]`.
        if let index = CommandLine.arguments.firstIndex(of: "--encode-file") {
            EncodeFileCommand.run(arguments: Array(CommandLine.arguments[(index + 1)...]))
        }
        #endif
    }

    var body: some Scene {
        Window("Sigil", id: "main") {
            MainView().environmentObject(model)
        }
        .defaultSize(width: 960, height: 640)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Sigil") { openWindow(id: "about") }
            }
            CommandGroup(after: .newItem) {
                Button("Find Key\u{2026}") {
                    NSApp.activate(ignoringOtherApps: true)
                    openWindow(id: "main")
                    model.showFindKey = true
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
            }
            CommandGroup(replacing: .help) {
                Button("Sigil Help") { openWindow(id: "help") }
                    .keyboardShortcut("?", modifiers: .command)
            }
        }

        Settings {
            SettingsView().environmentObject(model)
        }

        Window("About Sigil", id: "about") {
            AboutView().environmentObject(model)
        }
        .windowResizability(.contentSize)
        .windowStyle(.hiddenTitleBar)

        Window("Sigil Help", id: "help") {
            HelpView()
        }
        .defaultSize(width: 820, height: 600)
    }
}
