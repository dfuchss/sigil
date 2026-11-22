#if DEBUG
import Foundation
import os
import SigilCore

/// Hidden test entry point: `Sigil --decode-file <path>...` sends each file through the helper's
/// non-interactive decode (exactly what the Mail extension does) and prints/logs a summary of the outcome.
/// Never prints or logs plaintext.
enum DecodeFileCommand {
    private static let logger = Logger(subsystem: "org.fuchss.sigil", category: "app")

    static func run(paths: [String]) -> Never {
        for path in paths {
            let name = (path as NSString).lastPathComponent
            let summary: String
            if let data = FileManager.default.contents(atPath: path) {
                summary = describe(data)
            } else {
                summary = "cannot read file"
            }
            let line = "\(name): \(summary)"
            print(line)
            logger.info("decode-file \(line, privacy: .private)")
        }
        exit(EXIT_SUCCESS)
    }

    private static func describe(_ data: Data) -> String {
        let classification = PGPDetector.classify(messageData: data)
        guard classification != .none else { return "not PGP (no helper call)" }
        let started = Date()
        do {
            guard let outcome = try HelperClient.shared.decodeSync(message: data, interactive: false, timeout: 8) else {
                return "helper: not PGP"
            }
            let seconds = String(format: "%.2f", Date().timeIntervalSince(started))
            let p = DecodePresentation.make(outcome: outcome, original: data)
            var parts = ["\(classification.rawValue) in \(seconds) s",
                         "encrypted=\(outcome.encrypted)", "signed=\(outcome.signed)", "partial=\(outcome.partial)",
                         "needsPassphrase=\(outcome.needsPassphrase)",
                         "decoded=\(outcome.message.map { "\($0.count) bytes" } ?? "none")"]
            parts += outcome.signers.map {
                "signer[\($0.status.rawValue), validity \($0.validity?.rawValue ?? "none"), \($0.fingerprint ?? $0.keyID ?? "?")]"
            }
            if let error = outcome.error { parts.append("error=\"\(error)\"") }
            parts.append("| Mail: isEncrypted=\(p.isEncrypted)")
            parts += p.signers.map { "label=\"\($0.label)\"" }
            if let e = p.signingError { parts.append("signingError=\"\(e)\"") }
            if let e = p.encryptionError { parts.append("encryptionError=\"\(e)\"") }
            if let b = p.banner { parts.append("banner=\"\(b.title)\" [\(b.actionTitle)]") }
            if p.blocksRemoteContent { parts.append("blocksRemoteContent") }
            return parts.joined(separator: " ")
        } catch {
            let p = DecodePresentation.helperFailure(original: data, title: "Sigil helper not reachable.")
            return "helper failed: \(error.localizedDescription) | Mail: banner=\"\(p.banner?.title ?? "")\" [Retry]"
        }
    }
}
#endif
