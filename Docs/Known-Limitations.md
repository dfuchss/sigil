# Known limitations

- **Drafts are not encrypted.** MailKit only calls the extension when a message is sent. Mail saves drafts (locally and to the IMAP Drafts mailbox) before that, so drafts of an encrypted message are stored there in plaintext. Sigil itself never writes message content to disk: messages go to gpg through pipes only.
- **No red badge.** Mail's signature badge cannot be changed by an extension and cannot show a red state for one, which is why Sigil adds the red and yellow boxes and the banner itself.
- **Message actions are not usable.** MailKit message actions are not usable for Sigil's purposes, so it has none.
- **Previews of truncated mail** (messages Mail has not downloaded completely) show "Encrypted message" until you open them.
- **Encrypted means everyone.** When encryption is on, every To, Cc and Bcc recipient needs a usable key; otherwise Sigil blocks sending and never falls back to plaintext. Bcc recipients are encrypted to as hidden recipients (`--hidden-recipient`, key ID 0 in the message). The message is always encrypted to your own key too.
- **Headers stay readable.** PGP/MIME protects the body only; Subject, From, To and Cc are sent in clear.
- **Line endings.** Mail hands the extension messages with LF line endings; Sigil signs the CRLF-canonical form and hands the result back with LF (`HelperClient.outgoingLineEndings`), which Mail turns into CRLF on the wire. The signature stays valid either way, as every line ends in CRLF before conversion.
- **No automatic updates.** Run `scripts/install.sh` again with a newer checkout.
- **Personal Team certificates expire.** A build signed with a free Apple ID's Personal Team certificate stops working when the certificate expires (about a year); rebuild and reinstall with `scripts/install.sh`. A paid Developer ID would avoid this.
- **Only keys with an email address** are used.
