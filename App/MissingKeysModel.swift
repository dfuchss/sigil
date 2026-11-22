import AppKit
import os
import SigilCore
import SwiftUI

/// Unknown signing keys the helper noted while verifying incoming mail, plus the key search sheet state.
@MainActor
final class MissingKeysModel: ObservableObject {
    /// The key search for one entry: candidates found in the helper's temporary keyring, the user's selection and
    /// the result of each import.
    struct Search: Identifiable {
        enum Phase {
            case searching
            case results(KeySearchResult)
            case failed(String)
        }
        enum Outcome: Equatable {
            case importing
            case imported(KeyImportResult)
            case failed(String)
        }

        /// The missing-keys entry searched for; nil for a manual "Find Key" search.
        let entry: MissingKeyEntry?
        let query: KeyQuery?
        var phase: Phase = .searching
        var selection: Set<String> = []
        var outcomes: [String: Outcome] = [:]
        var id: String { entry?.id ?? "find" }

        var candidates: [KeyCandidate] {
            if case let .results(result) = phase { return result.candidates }
            return []
        }
        var title: String {
            if let entry { return "Keys for \(entry.senderEmail ?? "0x" + entry.keyID)" }
            return "Find Key"
        }
        func isPreselected(_ c: KeyCandidate) -> Bool {
            if let query { return c.isPreselected(forQuery: query) }
            return c.isPreselected(forSender: entry?.senderEmail)
        }
        func isValid(_ c: KeyCandidate) -> Bool {
            if let query { return c.isValid(forQuery: query) }
            return c.isValid(forSender: entry?.senderEmail)
        }
        var isImporting: Bool { outcomes.values.contains(.importing) }
        var finished: Bool { !outcomes.isEmpty && !isImporting }
    }

    @Published var entries: [MissingKeyEntry] = []
    @Published var error: String?
    @Published var showDismissed = false
    @Published var search: Search?

    private let logger = Logger(subsystem: "org.fuchss.sigil", category: "app")
    private let client = HelperClient.shared
    private var token: String?

    var visibleEntries: [MissingKeyEntry] {
        entries.filter { showDismissed || !$0.dismissed }.sorted { $0.lastSeen > $1.lastSeen }
    }

    var dismissedCount: Int { entries.filter(\.dismissed).count }

    func refresh() async {
        #if DEBUG
        if DebugLaunch.demo { if entries.isEmpty { entries = DemoData.missingKeys() }; return }
        #endif
        do {
            entries = try await client.listMissingKeys()
            error = nil
        } catch {
            self.error = error.localizedDescription
            logger.error("listMissingKeys failed: \(error.localizedDescription, privacy: .private)")
        }
    }

    func setDismissed(_ entry: MissingKeyEntry, _ dismissed: Bool) async {
        #if DEBUG
        if DebugLaunch.demo {
            if let i = entries.firstIndex(where: { $0.id == entry.id }) { entries[i].dismissed = dismissed }
            return
        }
        #endif
        do {
            entries = try await client.setMissingKey(id: entry.id, dismissed: dismissed)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func remove(_ entry: MissingKeyEntry) async {
        #if DEBUG
        if DebugLaunch.demo { entries.removeAll { $0.id == entry.id && $0.dismissed }; return }
        #endif
        do {
            entries = try await client.removeMissingKey(id: entry.id)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func removeAllDismissed() async {
        #if DEBUG
        if DebugLaunch.demo { entries.removeAll(where: \.dismissed); return }
        #endif
        do {
            _ = try await client.removeDismissedMissingKeys()
            await refresh()
        } catch {
            self.error = error.localizedDescription
        }
    }

    // MARK: Search and import

    func startSearch(_ entry: MissingKeyEntry) async {
        search = Search(entry: entry, query: nil)
        do {
            let result = try await demoOr(email: entry.senderEmail ?? "") { try await client.searchMissingKey(id: entry.id) }
            guard search?.id == entry.id else {
                try? await discard(token: result.token)
                return
            }
            token = result.token
            search?.phase = .results(result)
            search?.selection = Set(result.candidates.filter { search?.isPreselected($0) == true }.map(\.fingerprint))
        } catch {
            if search?.id == entry.id { search?.phase = .failed(error.localizedDescription) }
            logger.error("key search failed: \(error.localizedDescription, privacy: .private)")
        }
    }

    private func discard(token: String) async throws {
        #if DEBUG
        if DebugLaunch.demo { return }
        #endif
        try await client.discardKeySearch(token: token)
    }

    /// The demo result under `--demo` (DEBUG only), otherwise the helper's.
    private func demoOr(email: String, _ real: () async throws -> KeySearchResult) async throws -> KeySearchResult {
        #if DEBUG
        if DebugLaunch.demo { return DemoData.search(email: email) }
        #endif
        return try await real()
    }

    /// Manual search. An invalid query is rejected here, without calling the helper.
    @Published var findError: String?

    func startFind(text: String) async {
        guard let query = KeyQuery.parse(text) else {
            findError = "Enter an email address, a fingerprint (40 or 64 hex digits) or a 16-digit key ID."
            return
        }
        findError = nil
        if let old = token { self.token = nil; try? await discard(token: old) }
        search = Search(entry: nil, query: query)
        do {
            let result = try await demoOr(email: query.demoEmail) { try await client.searchKeys(query: text) }
            guard search?.query == query else {
                try? await discard(token: result.token)
                return
            }
            token = result.token
            search?.phase = .results(result)
            search?.selection = Set(result.candidates.filter { search?.isPreselected($0) == true }.map(\.fingerprint))
        } catch {
            if search?.query == query { search?.phase = .failed(error.localizedDescription) }
        }
    }

    /// Runs the current search again (after the keyserver setup).
    func repeatSearch() async {
        guard let current = search else { return }
        if let entry = current.entry {
            await startSearch(entry)
        } else if let query = current.query {
            await startFind(text: Self.text(of: query))
        }
    }

    private static func text(of query: KeyQuery) -> String {
        switch query {
        case let .email(value), let .fingerprint(value), let .keyID(value): return value
        }
    }

    func toggle(_ candidate: KeyCandidate) {
        guard search?.isImporting == false else { return }
        if search?.selection.contains(candidate.fingerprint) == true {
            search?.selection.remove(candidate.fingerprint)
        } else {
            search?.selection.insert(candidate.fingerprint)
        }
    }

    func selectAllValid() {
        guard let search else { return }
        self.search?.selection = Set(search.candidates.filter { search.isValid($0) }.map(\.fingerprint))
    }

    /// Imports every ticked candidate, one after the other (each exported individually from the temporary keyring).
    func importSelected() async {
        guard let token, let search else { return }
        #if DEBUG
        if DebugLaunch.demo { return }
        #endif
        let chosen = search.candidates.filter { search.selection.contains($0.fingerprint) }
        for candidate in chosen {
            self.search?.outcomes[candidate.fingerprint] = .importing
            do {
                let result = try await client.importCandidateKey(token: token, fingerprint: candidate.fingerprint)
                self.search?.outcomes[candidate.fingerprint] = .imported(result)
                logger.info("imported key \(result.fingerprint, privacy: .private), matches signature: \(result.matchesSignature)")
            } catch {
                self.search?.outcomes[candidate.fingerprint] = .failed(error.localizedDescription)
            }
        }
        await refresh()
    }

    /// Closes the sheet and deletes the helper's temporary keyring; nothing that was not imported is kept.
    func closeSearch() async {
        let token = self.token
        self.token = nil
        search = nil
        if let token { try? await discard(token: token) }
        await refresh()
    }
}

private extension KeyQuery {
    var demoEmail: String {
        if case let .email(value) = self { return value }
        return "dave@example.org"
    }
}
