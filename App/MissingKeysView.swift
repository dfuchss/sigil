import AppKit
import SigilCore
import SwiftUI

/// Keys of signed messages Sigil could not check, with Fetch (opens the key search sheet) and Dismiss per entry.
struct MissingKeysView: View {
    @EnvironmentObject private var app: AppModel
    @StateObject private var model = MissingKeysModel()
    @State private var confirmRemoveAll = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Keys of signed messages Sigil could not check. Fetch looks them up with your gpg configuration "
                     + "(auto-key-locate, dirmngr keyserver) and lets you choose what to import.")
                    .font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                HStack {
                    Toggle("Show dismissed (\(model.dismissedCount))", isOn: $model.showDismissed)
                    if model.showDismissed && model.dismissedCount > 0 {
                        Spacer()
                        Button("Remove all dismissed…") { confirmRemoveAll = true }
                    }
                }
            }
            .padding([.horizontal, .top], 16).padding(.bottom, 8)
            if let error = model.error { Text(error).foregroundStyle(.red).padding(.horizontal, 16) }
            if model.visibleEntries.isEmpty && model.error == nil {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.seal").font(.system(size: 36)).foregroundStyle(.secondary)
                    Text("No missing keys").font(.headline).foregroundStyle(.secondary)
                    Text("Keys of unknown signers show up here.").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.visibleEntries) { row($0) }
            }
        }
        // minHeight 0: otherwise the wrapping explanation reports a huge minimum height when measured narrow, and
        // NavigationSplitView grows past the window, pushing the sidebar rows and this header off-screen.
        .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity, alignment: .top)
        .task { await model.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refresh() }
        }
        .confirmationDialog("Remove \(model.dismissedCount) dismissed keys?", isPresented: $confirmRemoveAll) {
            Button("Remove", role: .destructive) { Task { await model.removeAllDismissed() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("They come back as new entries if a message signed with one of them arrives.")
        }
        .sheet(isPresented: Binding(get: { model.search != nil }, set: { if !$0 { Task { await closeSheet() } } })) {
            KeySearchSheet(model: model, close: { Task { await closeSheet() } })
        }
    }

    private func closeSheet() async {
        await model.closeSearch()
        await app.refresh()
    }

    private func row(_ entry: MissingKeyEntry) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.senderEmail ?? "Unknown sender") + Text(entry.dismissed ? "  (dismissed)" : "")
                    .foregroundColor(.secondary)
                Text(entry.fingerprint.map(Fingerprint.grouped) ?? "Key ID 0x\(entry.keyID)")
                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                Text("Last seen \(entry.lastSeen.formatted(date: .abbreviated, time: .shortened)) · "
                     + "\(entry.count) message\(entry.count == 1 ? "" : "s")")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Fetch…") { Task { await model.startSearch(entry) } }
            if entry.dismissed {
                Button("Restore") { Task { await model.setDismissed(entry, false) } }
                Button("Remove") { Task { await model.remove(entry) } }
            } else {
                Button("Dismiss") { Task { await model.setDismissed(entry, true) } }
            }
        }
        .padding(.vertical, 4)
    }
}

/// Lists every candidate key found for a missing key; the user ticks what to import.
struct KeySearchSheet: View {
    @EnvironmentObject private var app: AppModel
    @ObservedObject var model: MissingKeysModel
    @State private var confirmingKeyserver = false
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.search?.title ?? "Keys").font(.title3.bold())
            Text("Found with your gpg configuration. Nothing is added to your keyring until you press Import; "
                 + "compare fingerprints with the sender before you rely on a key.")
                .font(.callout).foregroundStyle(.secondary)
            content
            Divider()
            footer
        }
        .padding(20)
        .frame(width: 600, height: 480)
        .keyserverSetupDialog(isPresented: $confirmingKeyserver) {
            // Search again: the helper has just got a keyserver.
            Task { await model.repeatSearch() }
        }
    }

    @ViewBuilder private var content: some View {
        switch model.search?.phase {
        case .none, .searching?:
            VStack(spacing: 10) {
                ProgressView()
                Text("Searching…").foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case let .failed(message)?:
            Text(message).foregroundStyle(.red).textSelection(.enabled).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        case let .results(result)?:
            if result.candidates.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("No key found.", systemImage: "magnifyingglass").font(.headline)
                        if result.problems.isEmpty {
                            Text(result.message ?? "").font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                        } else {
                            ForEach(result.problems) { problem in problemView(problem) }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            } else {
                List(result.candidates) { candidate in candidateRow(candidate) }
                    .listStyle(.bordered)
            }
        }
    }

    private func problemView(_ problem: SearchProblem) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(problem.source).font(.caption.bold()).foregroundStyle(.secondary)
            Text(problem.summary).textSelection(.enabled)
            if problem.kind == .noKeyserver {
                Button("Set up keys.openpgp.org…") { confirmingKeyserver = true }
            }
            if problem.details != problem.summary, !problem.details.isEmpty {
                DisclosureGroup("Details") {
                    Text(problem.details).font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.caption)
            }
        }
        .padding(.vertical, 4)
    }

    private func candidateRow(_ candidate: KeyCandidate) -> some View {
        let search = model.search
        let outcome = search?.outcomes[candidate.fingerprint]
        let dimmed = candidate.expired || candidate.revoked || (candidate.alreadyInKeyring && outcome == nil)
        return HStack(alignment: .top, spacing: 10) {
            Toggle("", isOn: Binding(get: { search?.selection.contains(candidate.fingerprint) == true },
                                     set: { _ in model.toggle(candidate) }))
                .labelsHidden()
                .disabled(search?.isImporting == true || search?.finished == true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    if candidate.matchesSignature { Badge("Signed this message", color: .green) }
                    if candidate.matchesQuery { Badge("Exact match", color: .green) }
                    if candidate.alreadyInKeyring { Badge("Already imported", color: .secondary) }
                    ForEach(candidate.sources, id: \.self) { Badge($0, color: .blue) }
                    if candidate.isKeyserverOnly { Badge("Keyserver: address not verified", color: .orange) }
                    if candidate.revoked { Badge("Revoked", color: .red) }
                    if candidate.expired { Badge("Expired", color: .orange) }
                    if !candidate.hasEmailUserID { Badge("No email user ID", color: .orange) }
                }
                ForEach(candidate.userIDs, id: \.uid) { Text($0.uid).fontWeight(.medium) }
                Text(Fingerprint.grouped(candidate.fingerprint))
                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                if let created = candidate.created {
                    Text("Created \(created.formatted(date: .abbreviated, time: .omitted))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                outcomeView(outcome)
            }
            .opacity(dimmed ? 0.55 : 1)
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    @ViewBuilder private func outcomeView(_ outcome: MissingKeysModel.Search.Outcome?) -> some View {
        switch outcome {
        case .importing?:
            HStack { ProgressView().controlSize(.small); Text("Importing…").font(.caption) }
        case let .imported(result)?:
            // A manual "Find Key" search has no signature to match, so only warn when there was one.
            if result.matchesSignature || model.search?.entry == nil {
                Label("Imported", systemImage: "checkmark.circle").font(.caption).foregroundStyle(.green)
            } else {
                Label("Imported, but it doesn't match the signature", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
            }
        case let .failed(message)?:
            Text(message).font(.caption).foregroundStyle(.red).textSelection(.enabled)
        case nil:
            EmptyView()
        }
    }

    private var footer: some View {
        HStack {
            if let search = model.search, !search.candidates.isEmpty, !search.finished {
                Button("Select all valid") { model.selectAllValid() }.disabled(search.isImporting)
            }
            Spacer()
            if let search = model.search, search.finished {
                Button("Done", action: close).keyboardShortcut(.defaultAction)
            } else {
                Button("Cancel", action: close).keyboardShortcut(.cancelAction)
                Button("Import") { Task { await model.importSelected() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled((model.search?.selection.isEmpty ?? true) || model.search?.isImporting == true)
            }
        }
    }
}

/// "Find Key": the user types an email address, fingerprint or key ID; results use the same sheet.
struct FindKeySheet: View {
    @EnvironmentObject private var app: AppModel
    @StateObject private var model = MissingKeysModel()
    @State private var text = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        if model.search == nil {
            VStack(alignment: .leading, spacing: 12) {
                Text("Find Key").font(.title3.bold())
                Text("Enter an email address, a fingerprint or a 16-digit key ID. Sigil searches with your gpg "
                     + "configuration and imports nothing until you choose.")
                    .font(.callout).foregroundStyle(.secondary)
                TextField("alice@example.org or fingerprint", text: $text)
                    .onSubmit { Task { await model.startFind(text: text) } }
                if let error = model.findError { Text(error).font(.caption).foregroundStyle(.red) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Search") { Task { await model.startFind(text: text) } }
                        .keyboardShortcut(.defaultAction).disabled(text.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .padding(20).frame(width: 460)
            #if DEBUG
            .task {
                if DebugLaunch.demo, model.search == nil { text = "dave@example.org"; await model.startFind(text: text) }
            }
            #endif
        } else {
            KeySearchSheet(model: model, close: {
                Task {
                    await model.closeSearch()
                    await app.refresh()
                    dismiss()
                }
            })
        }
    }
}
