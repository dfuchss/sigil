import Foundation

/// Produces RFC 3156 PGP/MIME messages from complete RFC 822 messages.
public enum PGPMIMEEncoder {
    /// Signs the body entity and returns the full message (outer headers kept) as multipart/signed.
    public static func sign(message: Data, signer: String, gpg: any GPGRunning) throws -> Data {
        let msg = RFC822Message(data: message)
        let entity = Canonicalizer.canonicalize(entity: msg.bodyEntity)
        let (signature, micalg) = try gpg.sign(entity, signerFingerprint: signer)
        let signed = MIMEBuilder.multipartSigned(signedEntity: entity, signature: signature, micalg: micalg)
        return RFC822Message.combine(outerHeaders: msg.outerHeaders, bodyEntity: signed)
    }

    /// Encrypts (and, if `signer` is given, signs in the same gpg call) the canonicalized body entity
    /// and returns the full message as multipart/encrypted.
    public static func encrypt(message: Data, recipients: [String], hidden: [String] = [], signer: String?,
                               gpg: any GPGRunning) throws -> Data {
        let msg = RFC822Message(data: message)
        let entity = Canonicalizer.canonicalize(entity: msg.bodyEntity)
        let ciphertext = try gpg.encrypt(entity, recipients: recipients, hiddenRecipients: hidden, signerFingerprint: signer)
        let encrypted = MIMEBuilder.multipartEncrypted(armoredCiphertext: ciphertext)
        return RFC822Message.combine(outerHeaders: msg.outerHeaders, bodyEntity: encrypted)
    }
}
