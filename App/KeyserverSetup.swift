import SwiftUI

extension View {
    /// The confirmation before Sigil writes `keyserver hkps://keys.openpgp.org` into dirmngr.conf. Nothing is
    /// written unless the user confirms. `done` runs after the helper has made the change.
    func keyserverSetupDialog(isPresented: Binding<Bool>, done: @escaping () -> Void = {}) -> some View {
        modifier(KeyserverSetupDialog(isPresented: isPresented, done: done))
    }
}

private struct KeyserverSetupDialog: ViewModifier {
    @EnvironmentObject private var model: AppModel
    @Binding var isPresented: Bool
    let done: () -> Void

    func body(content: Content) -> some View {
        let path = model.keyserver?.configPath ?? "~/.gnupg/dirmngr.conf"
        content.confirmationDialog("Set up keys.openpgp.org?", isPresented: $isPresented) {
            Button("Change dirmngr.conf") {
                Task {
                    await model.fixKeyserver()
                    done()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Sigil adds the line \"keyserver hkps://keys.openpgp.org\" to \(path) (the file is created if it does not "
                 + "exist) and reloads dirmngr. keys.openpgp.org only serves keys whose email addresses have been "
                 + "verified by their owners.")
        }
    }
}
