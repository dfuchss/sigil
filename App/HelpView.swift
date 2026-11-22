import SwiftUI

/// The in-app help: topics in a sidebar, the selected topic as scrollable rich text. The text lives in
/// `HelpContent.swift`.
struct HelpView: View {
    @State private var selection: HelpTopic.ID? = HelpContent.topics.first?.id

    var body: some View {
        NavigationSplitView {
            List(HelpContent.topics, selection: $selection) { topic in
                Label(topic.title, systemImage: topic.symbol).tag(topic.id)
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 230, max: 280)
        } detail: {
            if let topic = HelpContent.topics.first(where: { $0.id == selection }) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(topic.title).font(.largeTitle.bold())
                        ForEach(Array(topic.blocks.enumerated()), id: \.offset) { _, block in render(block) }
                    }
                    .frame(maxWidth: 640, alignment: .leading)
                    .padding(24)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .navigationTitle(topic.title)
            }
        }
        .frame(minWidth: 680, minHeight: 420)
    }

    @ViewBuilder private func render(_ block: HelpBlock) -> some View {
        switch block {
        case let .heading(text):
            Text(text).font(.title3.bold()).padding(.top, 6)
        case let .paragraph(text):
            Text(Self.markdown(text)).fixedSize(horizontal: false, vertical: true)
        case let .bullets(items):
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text("\u{2022}")
                        Text(Self.markdown(item)).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        case let .code(text):
            Text(text)
                .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
    }

    private static func markdown(_ text: String) -> AttributedString {
        (try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(text)
    }
}
