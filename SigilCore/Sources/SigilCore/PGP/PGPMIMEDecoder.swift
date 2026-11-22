import Foundation

/// Decrypts / verifies PGP/MIME and inline PGP messages.
public enum PGPMIMEDecoder {
    /// At most this many PGP/MIME parts and armor blocks per message; above it no gpg runs.
    public static let maxPGPParts = 16

    /// Returns nil for messages without PGP content. Otherwise returns the decoded message
    /// (outer headers + plaintext body entity) and the security state. On decryption failure,
    /// `message` is nil and `error` is set — no partial plaintext is ever returned.
    ///
    /// With `interactive == false` (the default) gpg never prompts for a passphrase; if one is needed and not
    /// cached by gpg-agent, the outcome has `needsPassphrase == true`.
    ///
    /// Encrypted content is only decrypted when it is the whole message (`PGPCensus.encryptedIsWholeMessage`).
    /// Otherwise (encrypted parts next to other content: the EFAIL / decryption-oracle setup) nothing is decrypted
    /// and the outcome has `mixedEncryption == true` and the original message, unless `allowMixed` is set (an
    /// explicit user request; the caller must then never hand the plaintext back into a message Mail renders).
    public static func decode(message: Data, gpg: any GPGRunning, interactive: Bool = false,
                              allowMixed: Bool = false) -> DecodeOutcome? {
        let classification = PGPDetector.classify(messageData: message)
        guard classification != .none else { return nil }

        let msg = RFC822Message(data: message)
        let root = MIMEEntity(data: msg.bodyEntity)
        let census = PGPCensus.of(root)
        if census.parts > maxPGPParts || census.truncated {
            return DecodeOutcome(message: nil, classification: classification, encrypted: false, signed: false,
                                 partial: false, signers: [],
                                 error: GPGError.tooManyParts(max(census.parts, maxPGPParts + 1)).errorDescription,
                                 needsPassphrase: false)
        }
        let mixedEncryption = census.encrypted > 0 && !census.encryptedIsWholeMessage
        if mixedEncryption && !allowMixed { return mixedOutcome(message, classification) }

        var state = State(gpg: gpg, interactive: interactive)
        state.refuseEncrypted = !allowMixed && census.encrypted == 0
        state.contentLeafCount = root.leaves.filter { !$0.rawBody.allSatisfy(isWhitespace) }.count
        var replacements: [(Range<Int>, [UInt8])] = []
        walk(root, isRoot: true, state: &state, replacements: &replacements)
        if state.unexpectedEncryption && !allowMixed { return mixedOutcome(message, classification) }

        if let fatal = state.fatal {
            return DecodeOutcome(
                message: nil, classification: classification,
                encrypted: state.encrypted || classification == .pgpMimeEncrypted || state.attemptedDecryption,
                signed: false, partial: state.partial, signers: [],
                error: (fatal as? LocalizedError)?.errorDescription ?? String(describing: fatal),
                needsPassphrase: (fatal as? GPGError) == .needsPassphrase
            )
        }

        let newBody = Bytes.splice([UInt8](root.source), replacements)
        let decoded = RFC822Message.combine(outerHeaders: msg.outerHeaders, bodyEntity: Data(newBody))
        let fromEmail = msg.header("From").flatMap { EmailAddress.parse($0).email }
        let signers = signerInfos(state.signatures, fromEmail: fromEmail, gpg: gpg)
        return DecodeOutcome(
            message: decoded, classification: classification,
            encrypted: state.encrypted, signed: !signers.isEmpty, partial: state.partial,
            signers: signers, error: state.verifyError, needsPassphrase: false
        )
    }

    /// The original message, nothing decrypted: encrypted content mixed with other content.
    static func mixedOutcome(_ message: Data, _ classification: MessageClassification) -> DecodeOutcome {
        DecodeOutcome(message: message, classification: classification, encrypted: false, signed: false,
                      partial: true, signers: [], error: nil, needsPassphrase: false, mixedEncryption: true)
    }

    struct State {
        let gpg: any GPGRunning
        let interactive: Bool
        var signatures: [SignatureResult] = []
        var encrypted = false
        var attemptedDecryption = false
        var partial = false
        var fatal: Error? = nil
        var verifyError: String? = nil
        var contentLeafCount = 0
        /// The census found no encrypted content: a MESSAGE block that turns out to be encrypted anyway (the first
        /// packet hid it) is not shown, and the message is treated as mixed.
        var refuseEncrypted = false
        var unexpectedEncryption = false
    }

    static func isWhitespace(_ c: UInt8) -> Bool {
        c == Bytes.sp || c == Bytes.tab || c == Bytes.cr || c == Bytes.lf
    }

    static func walk(_ e: MIMEEntity, isRoot: Bool, state: inout State, replacements: inout [(Range<Int>, [UInt8])]) {
        guard state.fatal == nil else { return }
        if e.isPGPMIMEEncrypted {
            if !isRoot { state.partial = true }
            if let plain = handleEncrypted(e, state: &state) { replacements.append((e.range, [UInt8](plain))) }
        } else if e.isPGPMIMESigned {
            if !isRoot { state.partial = true }
            if let content = verifySigned(e, state: &state) { replacements.append((e.range, [UInt8](content))) }
        } else if !e.children.isEmpty {
            for c in e.children { walk(c, isRoot: false, state: &state, replacements: &replacements) }
        } else if PGPDetector.isInlineCandidate(e) {
            if let part = handleInline(e, state: &state) { replacements.append((e.range, [UInt8](part))) }
        }
    }

    // MARK: PGP/MIME encrypted

    static func handleEncrypted(_ e: MIMEEntity, state: inout State) -> Data? {
        state.attemptedDecryption = true
        guard e.children.count >= 2 else {
            state.fatal = GPGError.malformedMessage("multipart/encrypted needs two parts")
            return nil
        }
        let dataPart = e.children.first { $0.contentType.mimeType == "application/octet-stream" } ?? e.children[1]
        let result: DecryptResult
        do {
            result = try state.gpg.decrypt(dataPart.decodedBody, interactive: state.interactive)
        } catch {
            state.fatal = error
            return nil
        }
        guard result.wasEncrypted else {
            state.fatal = GPGError.malformedMessage("multipart/encrypted does not contain encrypted data")
            return nil
        }
        state.encrypted = true
        state.signatures += result.signatures

        let inner = ensureEntity(result.plaintext)
        let innerEntity = MIMEEntity(data: inner)
        // Recurse once: signed inside encrypted.
        if innerEntity.isPGPMIMESigned, let content = verifySigned(innerEntity, state: &state) {
            return content
        }
        return inner
    }

    /// Adds a default text/plain header section if the decrypted data has no MIME headers.
    static func ensureEntity(_ data: Data) -> Data {
        let b = [UInt8](data)
        let parsed = MIMEHeaders.parse(b, 0, b.count)
        if parsed.fields.contains(where: { $0.lowercasedName.hasPrefix("content-") }) { return data }
        var out = Data("Content-Type: text/plain; charset=utf-8\r\n\r\n".utf8)
        out.append(data)
        return out
    }

    // MARK: PGP/MIME signed

    /// Verifies a multipart/signed entity and returns the bytes of the signed content part.
    static func verifySigned(_ e: MIMEEntity, state: inout State) -> Data? {
        guard e.children.count == 2 else {
            state.verifyError = GPGError.malformedMessage("multipart/signed needs exactly two parts").errorDescription
            state.signatures.append(SignatureResult(status: .error))
            return e.children.first?.rawData
        }
        let content = e.children[0]
        let signature = e.children[1].decodedBody
        do {
            let sigs = try state.gpg.verify(LineEndings.toCRLF(content.rawData), detachedSignature: signature)
            state.signatures += sigs
        } catch {
            state.verifyError = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            state.signatures.append(SignatureResult(status: .error))
        }
        return content.rawData
    }

    // MARK: Inline PGP

    static func handleInline(_ e: MIMEEntity, state: inout State) -> Data? {
        guard let text = e.text else { return nil }
        let tb = [UInt8](text.utf8)
        let blocks = Armor.blocks(in: Data(tb))
        guard !blocks.isEmpty else { return nil }

        var reps: [(Range<Int>, [UInt8])] = []
        for block in blocks {
            switch block.kind {
            case .message:
                state.attemptedDecryption = true
                do {
                    let r = try state.gpg.decrypt(block.data, interactive: state.interactive)
                    if r.wasEncrypted && state.refuseEncrypted {
                        state.unexpectedEncryption = true
                        return nil
                    }
                    if r.wasEncrypted { state.encrypted = true }
                    state.signatures += r.signatures
                    reps.append((block.range, textBytes(r.plaintext)))
                } catch {
                    state.fatal = error
                    return nil
                }
            case .signedMessage:
                do {
                    let r = try state.gpg.verifyInline(block.data)
                    state.signatures += r.signatures
                    reps.append((block.range, textBytes(r.plaintext)))
                } catch {
                    state.verifyError = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
                    state.signatures.append(SignatureResult(status: .error))
                }
            }
        }

        // Text outside the armored blocks, or other content parts, is neither signed nor encrypted.
        let outside = Bytes.splice(tb, blocks.map { ($0.range, []) })
        if !outside.allSatisfy(isWhitespace) || state.contentLeafCount > 1 { state.partial = true }

        let newText = Bytes.splice(tb, reps)
        var out = Data()
        for f in e.headers.fields where !["content-type", "content-transfer-encoding"].contains(f.lowercasedName) {
            out.append(f.rawCRLF)
        }
        out.append(Data("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n".utf8))
        out.append(QuotedPrintable.encodeText(Data(newText)))
        return out
    }

    /// Plaintext as UTF-8 bytes with one trailing line break removed.
    static func textBytes(_ data: Data) -> [UInt8] {
        var b = [UInt8](Bytes.string([UInt8](data)).utf8)
        if b.last == Bytes.lf { b.removeLast(); if b.last == Bytes.cr { b.removeLast() } }
        return b
    }

    // MARK: Signers

    static func signerInfos(_ sigs: [SignatureResult], fromEmail: String?, gpg: any GPGRunning) -> [SignerInfo] {
        var cache: [String: [String]] = [:]
        return sigs.map { s in
            let fpr = s.primaryFingerprint ?? s.fingerprint
            // The signature is always reported; only the key's email user IDs (as listed) give the signer an
            // address. A key without any email user ID keeps email nil and never matches the sender.
            var email: String? = nil
            var matchesSender: Bool? = nil
            if let fpr, s.status != .noPublicKey {
                let emails: [String]
                if let c = cache[fpr] {
                    emails = c
                } else {
                    emails = ((try? gpg.listKeys(secret: false, patterns: [fpr])) ?? []).first?.emails ?? []
                    cache[fpr] = emails
                }
                if let fromEmail, emails.contains(fromEmail) {
                    email = fromEmail
                } else if let signatureEmail = s.email, emails.contains(signatureEmail) {
                    email = signatureEmail
                } else {
                    email = emails.first
                }
                if let fromEmail { matchesSender = email == fromEmail }
            }
            return SignerInfo(fingerprint: fpr, keyID: s.keyID, email: email, userID: s.userID,
                              validity: s.trust, status: s.status, created: s.created, matchesSender: matchesSender)
        }
    }
}

/// What PGP content a message has, counted without gpg.
struct PGPCensus: Equatable {
    /// PGP/MIME parts plus inline armor blocks.
    var parts = 0
    /// Parts or blocks that are (or may be) encrypted.
    var encrypted = 0
    /// A text part above the armor scan caps.
    var truncated = false
    /// The encrypted content is the whole message: a top-level multipart/encrypted, or a top-level text/plain whose
    /// body is exactly one armored PGP MESSAGE block (surrounding whitespace aside).
    var encryptedIsWholeMessage = false

    static func of(_ root: MIMEEntity) -> PGPCensus {
        var census = PGPCensus()
        count(root, into: &census)
        if census.encrypted == 1 && census.parts == 1 {
            if root.isPGPMIMEEncrypted {
                census.encryptedIsWholeMessage = true
            } else if root.children.isEmpty, PGPDetector.isInlineCandidate(root), let text = root.text {
                let bytes = [UInt8](text.utf8)
                let scan = Armor.scan(Data(bytes))
                if scan.blocks.count == 1, scan.blocks[0].kind == .message, !scan.unterminated {
                    let outside = Bytes.splice(bytes, [(scan.blocks[0].range, [])])
                    census.encryptedIsWholeMessage = outside.allSatisfy(PGPMIMEDecoder.isWhitespace)
                }
            }
        }
        return census
    }

    private static func count(_ e: MIMEEntity, into census: inout PGPCensus) {
        if e.isPGPMIMEEncrypted {
            census.parts += 1
            census.encrypted += 1
        } else if e.isPGPMIMESigned {
            census.parts += 1
        } else if !e.children.isEmpty {
            for child in e.children { count(child, into: &census) }
        } else if PGPDetector.isInlineCandidate(e), let text = e.text {
            let scan = Armor.scan(Data(text.utf8))
            census.parts += scan.blocks.count
            census.encrypted += scan.blocks.filter(Armor.mayBeEncrypted).count
            if scan.truncated { census.truncated = true }
        }
    }
}
