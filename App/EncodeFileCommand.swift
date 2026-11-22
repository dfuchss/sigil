#if DEBUG
import Foundation
import os
import SigilCore

/// Hidden test entry point: `Sigil --encode-file <in.eml> <out.eml> [--sign] [--encrypt]` sends the message
/// through the helper's encode exactly like the Mail extension's `encode` (To and Cc as recipients, Bcc hidden,
/// same line-ending handling) and writes the result. Recipients come from the message headers, split at commas
/// (enough for test messages). Prints/logs only a summary, never content.
enum EncodeFileCommand {
    private static let logger = Logger(subsystem: "org.fuchss.sigil", category: "app")

    static func run(arguments: [String]) -> Never {
        let paths = arguments.filter { !$0.hasPrefix("--") }
        let sign = arguments.contains("--sign"), encrypt = arguments.contains("--encrypt")
        guard paths.count == 2, let input = FileManager.default.contents(atPath: paths[0]) else {
            finish("usage: --encode-file <in.eml> <out.eml> [--sign] [--encrypt] (input must be readable)", ok: false)
        }
        let message = RFC822Message(data: input)
        let addresses: (String) -> [String] = { name in
            (message.header(name) ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }
        let from = addresses("From").first ?? ""
        let recipients = addresses("To") + addresses("Cc"), hidden = addresses("Bcc")

        let finished = DispatchSemaphore(value: 0)
        let box = ResultHolder()
        let started = Date()
        Task {
            do {
                box.result = .success(try await HelperClient.shared.encodeForMail(
                    message: input, sign: sign, encrypt: encrypt, from: from, recipients: recipients, hiddenRecipients: hidden))
            } catch {
                box.result = .failure(error)
            }
            finished.signal()
        }
        finished.wait()
        let seconds = String(format: "%.2f", Date().timeIntervalSince(started))
        do {
            let encoded = try box.result!.get()
            try encoded.write(to: URL(fileURLWithPath: paths[1]))
            finish("""
                encoded sign=\(sign) encrypt=\(encrypt) in \(seconds) s: \(input.count) -> \(encoded.count) bytes, \
                \(recipients.count) recipients, \(hidden.count) hidden, LF output \(LineEndings.usesBareLF(encoded)) \
                -> \((paths[1] as NSString).lastPathComponent)
                """, ok: true)
        } catch {
            finish("encode failed after \(seconds) s: \(error.localizedDescription) (nothing written)", ok: false)
        }
    }

    private static func finish(_ line: String, ok: Bool) -> Never {
        print(line)
        logger.info("encode-file \(line, privacy: .private)")
        exit(ok ? EXIT_SUCCESS : EXIT_FAILURE)
    }
}

private final class ResultHolder: @unchecked Sendable {
    var result: Result<Data, Error>?
}
#endif
