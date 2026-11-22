import AppKit
import MailKit
import SigilCore

/// Signer details shown when the user clicks the signature in the message header.
final class SignerDetailsViewController: MEExtensionViewController {
    private let details: [SignerDetails]

    init(details: [SignerDetails]) {
        self.details = details
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("not used") }

    override func loadView() {
        let sections = details.map { detail -> NSView in
            let grid = NSGridView(views: detail.rows.map { row in
                [SecurityViews.label(row.label + ":", secondary: true), SecurityViews.label(row.value, monospaced: row.label == "Fingerprint")]
            })
            grid.column(at: 0).xPlacement = .trailing
            grid.rowSpacing = 4
            var views: [NSView] = [SecurityViews.label(detail.title, bold: true), grid]
            if let hint = detail.hint { views.append(SecurityViews.label(hint, secondary: true)) }
            let stack = NSStackView(views: views)
            stack.orientation = .vertical
            stack.alignment = .leading
            stack.spacing = 8
            return stack
        }
        view = SecurityViews.container(sections.isEmpty ? [SecurityViews.label("No signature information.")] : sections)
    }
}

/// A short title and explanation (banner actions that need to tell the user something).
final class MessageInfoViewController: MEExtensionViewController {
    private let heading: String
    private let message: String

    init(heading: String, message: String) {
        self.heading = heading
        self.message = message
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("not used") }

    override func loadView() {
        view = SecurityViews.container([SecurityViews.label(heading, bold: true), SecurityViews.label(message)])
    }
}

/// Plaintext from "Decrypt anyway", as plain, selectable text in a scroll view (never rendered as HTML).
final class PlaintextViewController: MEExtensionViewController {
    private let heading: String
    private let note: String
    private let text: String

    init(heading: String, note: String, text: String) {
        self.heading = heading
        self.note = note
        self.text = text
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("not used") }

    override func loadView() {
        let scroll = NSTextView.scrollableTextView()
        if let textView = scroll.documentView as? NSTextView {
            textView.isEditable = false
            textView.isSelectable = true
            textView.isRichText = false
            textView.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
            textView.string = text
        }
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(equalToConstant: 320).isActive = true
        scroll.widthAnchor.constraint(equalToConstant: SecurityViews.width - 40).isActive = true
        view = SecurityViews.container([SecurityViews.label(heading, bold: true), SecurityViews.label(note, secondary: true),
                                        scroll])
    }
}

enum SecurityViews {
    static let width: CGFloat = 460

    static func label(_ text: String, bold: Bool = false, secondary: Bool = false, monospaced: Bool = false) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: text)
        field.isSelectable = true
        if bold {
            field.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
        } else if monospaced {
            field.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        }
        if secondary { field.textColor = .secondaryLabelColor }
        field.preferredMaxLayoutWidth = width - 40
        return field
    }

    static func container(_ views: [NSView]) -> NSView {
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.widthAnchor.constraint(equalToConstant: width).isActive = true
        return stack
    }
}
