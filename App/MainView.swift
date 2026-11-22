import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case overview, myKeys, publicKeys, missingKeys

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .myKeys: return "My Keys"
        case .publicKeys: return "Public Keys"
        case .missingKeys: return "Missing Keys"
        }
    }

    var symbol: String {
        switch self {
        case .overview: return "checklist"
        case .myKeys: return "key.fill"
        case .publicKeys: return "person.2.fill"
        case .missingKeys: return "questionmark.key.filled"
        }
    }
}

/// The main window: a sidebar with the sections and the selected section as detail.
struct MainView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: SidebarItem? = .overview
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $selection) { item in
                Label(item.title, systemImage: item.symbol).tag(item)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190, max: 260)
        } detail: {
            detail
                // A long text must never raise the split view's minimum height above the window (hides the sidebar).
                .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity, alignment: .top)
                .navigationTitle(selection?.title ?? "Sigil")
        }
        .frame(minWidth: 760, minHeight: 480)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { model.showFindKey = true } label: { Label("Find Key…", systemImage: "magnifyingglass") }
                    .help("Search for a key by email address, fingerprint or key ID")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { await model.refresh() }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .help("Check the helper, gpg and the key lists again")
                .disabled(model.isRefreshing)
            }
        }
        .task { await model.refresh() }
        #if DEBUG
        .onAppear { DebugLaunch.apply(selection: &selection, openWindow: openWindow, openSettings: openSettings, model: model) }
        #endif
        .sheet(isPresented: $model.showFindKey) { FindKeySheet().environmentObject(model) }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refresh() }
        }
    }

    @ViewBuilder private var detail: some View {
        switch selection ?? .overview {
        case .overview: OverviewView(goTo: { selection = $0 })
        case .myKeys: MyKeysView()
        case .publicKeys: PublicKeysView()
        case .missingKeys: MissingKeysView()
        }
    }
}

#if DEBUG
/// DEBUG-only screenshot aids: `--demo`, `--appearance light|dark` and
/// `--open overview|mykeys|publickeys|missing|settings|about|help|findkey`.
@MainActor enum DebugLaunch {
    /// `--demo`: fixed made-up data, the helper is never called (see `DemoData`).
    nonisolated static let demo = CommandLine.arguments.contains("--demo")

    static func value(_ flag: String) -> String? {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
        return args[i + 1]
    }

    static func apply(selection: inout SidebarItem?, openWindow: OpenWindowAction, openSettings: OpenSettingsAction, model: AppModel) {
        switch value("--appearance") {
        case "light": NSApp.appearance = NSAppearance(named: .aqua)
        case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
        default: break
        }
        switch value("--open") {
        case "overview": selection = .overview
        case "mykeys": selection = .myKeys
        case "publickeys": selection = .publicKeys
        case "missing": selection = .missingKeys
        case "findkey": model.showFindKey = true
        case "settings":
            openSettings()
        case "about": openWindow(id: "about")
        case "help": openWindow(id: "help")
        default: break
        }
    }
}
#endif
