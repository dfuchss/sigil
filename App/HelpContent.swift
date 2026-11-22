import Foundation

/// The help text. Edit the topics below; inline Markdown (**bold**, *italic*, `code`) works in paragraphs and bullets.
enum HelpBlock {
    case heading(String)
    case paragraph(String)
    case bullets([String])
    case code(String)
}

struct HelpTopic: Identifiable {
    let id: String
    let title: String
    let symbol: String
    let blocks: [HelpBlock]
}

enum HelpContent {
    static let topics: [HelpTopic] = [
        HelpTopic(id: "start", title: "Getting started", symbol: "flag", blocks: [
            .paragraph("Sigil adds OpenPGP signing, encryption and verification to Apple Mail. It uses the GnuPG you install yourself, so your keys stay where they are."),
            .heading("1. Install GnuPG and pinentry-mac"),
            .code("brew install gnupg pinentry-mac"),
            .paragraph("pinentry-mac lets gpg-agent ask for your passphrase in a normal macOS window. The Overview shows whether it is set up; **Settings > Advanced** can configure it for you."),
            .heading("2. Register the helper"),
            .paragraph("Sigil talks to gpg through a small background helper. Open **Settings > General** and press **Register**. If macOS asks for approval, open System Settings > General > Login Items & Extensions and allow Sigil."),
            .heading("3. Enable the extension in Mail"),
            .paragraph("Quit and reopen Mail, then choose **Mail > Settings > Extensions** and tick **Sigil**. After an update, check there that it is still ticked."),
            .heading("4. Have a key"),
            .paragraph("You need a secret key with an email address. If you have none:"),
            .code("gpg --quick-gen-key \"Your Name <you@example.org>\""),
            .paragraph("The Overview turns every item green when all of this is done."),
        ]),
        HelpTopic(id: "sending", title: "Sending mail", symbol: "paperplane", blocks: [
            .paragraph("When you write a message, Sigil adds its own sign and encrypt toggles to the compose window."),
            .bullets([
                "**Sign** needs a secret key whose email address matches the From address.",
                "**Encrypt** needs a public key for every recipient (To, Cc and Bcc). If one is missing, Sigil stops the sending instead of sending the message unencrypted.",
                "Encrypted messages are also encrypted **to yourself**, so you can read them in your Sent mailbox.",
                "Bcc recipients are encrypted to as hidden recipients.",
                "Keys that are not verified yet are used, and marked in the compose window: **Key not verified – compare the fingerprint**.",
            ]),
            .heading("Several keys for one address"),
            .paragraph("When a recipient has more than one usable key, Sigil uses exactly one: the key you prefer, otherwise a verified key. If none of the keys is verified or preferred, Sigil does not guess: the address is marked in the compose window and an encrypted message is not sent until you choose. Open **Public Keys** and use **Prefer for <address>** on the key you want; **Clear preference** undoes it. A preferred key that expires or is revoked is ignored automatically."),
        ]),
        HelpTopic(id: "reading", title: "Reading mail", symbol: "envelope.open", blocks: [
            .bullets([
                "A valid signature gets Mail's normal **signed badge**.",
                "Encrypted messages are decrypted when you open them; gpg may ask for your passphrase.",
                "Problems show a **banner** and a **box** at the top of the message text.",
            ]),
            .heading("The boxes"),
            .bullets([
                "**Red box**: the signature is invalid, or the message was modified. Do not trust the content.",
                "**Yellow box**: the signature could not be fully checked: the key is unknown, expired or revoked, the key does not belong to the From address (**Signed by a different address**), or only part of the message is signed.",
            ]),
            .paragraph("The banner and the missing signed badge are what counts; the box is only an extra, and a message could imitate it."),
            .heading("Encrypted parts mixed with other content"),
            .paragraph("Sigil only decrypts a message on opening when the encrypted content is the whole message. If encrypted parts are mixed with other content, the message is shown as received with a banner, because the other content could send the decrypted text out (EFAIL). **Decrypt anyway** shows the decrypted text in a separate Sigil window, never inside the message."),
            .paragraph("Mail cannot show a red badge for an extension, which is why Sigil adds the boxes itself. Only keys with an email address are used."),
        ]),
        HelpTopic(id: "missing", title: "Missing keys", symbol: "questionmark.key.filled", blocks: [
            .paragraph("When a signed message comes from someone whose key you do not have, Sigil notes the key under **Missing Keys** (only the key, the sender address and a count; never the subject or content)."),
            .bullets([
                "**Fetch…** looks the key up with your own gpg configuration (the `auto-key-locate` setting in gpg.conf, such as WKD, and the keyserver of dirmngr). Sigil has no server settings of its own.",
                "The lookup runs in a temporary keyring. A sheet lists **every key found**, with its fingerprint, user IDs, creation date and where it was found (`auto-key-locate`, which is usually WKD, or the keyserver).",
                "The key that signed the message is marked **Signed this message**. Keys found through `auto-key-locate` (WKD: published by the sender's domain) are ticked when they signed the message or carry the sender's address. Keys found only on a keyserver are never ticked, not even the signing key, and are marked **Keyserver: address not verified**: keyservers may not check that an address belongs to the key, so tick them only after comparing the fingerprint with the sender. Expired or revoked keys are dimmed.",
                "Tick the keys you want and press **Import**. Cancel imports nothing.",
                "**Dismiss** hides an entry; **Show dismissed** and **Restore** bring it back, and **Remove** (or **Remove all dismissed…**) deletes dismissed entries for good; the key is recorded as a new entry if it shows up again.",
            ]),
            .paragraph("**Find Key…** (toolbar, File menu or Overview, Shift-Cmd-F) searches the same way for any email address, fingerprint or 16-digit key ID you type. Keys found through `auto-key-locate` (WKD) for that address are ticked; keyserver-only keys are not. Keys you already have are marked **Already imported** and can be imported again to refresh them."),
            .paragraph("The entry disappears once a key that matches the signature has been imported."),
        ]),
        HelpTopic(id: "trust", title: "Trust and verification", symbol: "checkmark.shield", blocks: [
            .paragraph("Importing a key does not prove it belongs to the person. Sigil accepts unverified keys, but marks them, because a wrong key would let someone else read your mail or sign as the sender."),
            .bullets([
                "Compare the **fingerprint** with the sender through another channel: in person, by phone or on their website.",
                "Once it matches, certify the key locally so gpg treats it as valid:",
            ]),
            .code("gpg --lsign-key <fingerprint>"),
            .paragraph("A locally signed key counts as verified: Sigil prefers verified keys when a recipient has several, and the yellow box for unknown trust goes away."),
        ]),
        HelpTopic(id: "troubleshooting", title: "Troubleshooting", symbol: "wrench.and.screwdriver", blocks: [
            .heading("The helper is not running"),
            .paragraph("Open the Overview. If the helper is not registered or not answering, use **Settings > General > Register**, approve it in Login Items & Extensions if asked, then press Refresh. If gpg is reported as not found, set its path in **Settings > General**."),
            .heading("Mail does not use the extension"),
            .paragraph("Quit Mail completely (Cmd+Q) and open it again, then check **Mail > Settings > Extensions** that Sigil is ticked."),
            .heading("Passphrase prompts"),
            .bullets([
                "No prompt appears: gpg-agent probably does not use pinentry-mac. Use **Settings > Advanced > Fix…**.",
                "You are asked again and again: gpg-agent keeps the passphrase only for a while (`default-cache-ttl` in gpg-agent.conf).",
                "To forget a cached passphrase, run `gpgconf --kill gpg-agent`.",
            ]),
            .heading("Finding keys fails / No keyserver available"),
            .bullets([
                "**No keyserver available:** gpg has no keyserver configured, so Find Key and Missing Keys only work via WKD. Use **Set up keys.openpgp.org…** in the Overview, **Settings > Advanced** or the search sheet; Sigil adds `keyserver hkps://keys.openpgp.org` to `dirmngr.conf` after you confirm. keys.openpgp.org only serves keys with verified email addresses.",
                "**Domain does not publish keys via WKD:** the sender's domain has no Web Key Directory. Try the keyserver, or ask the sender for their key.",
                "**The keyserver has no key for this address:** the owner has not uploaded or verified a key. Search by fingerprint, or ask the sender.",
                "**Network error:** check your connection and proxy settings, then search again. The sheet's **Details** show gpg's own message.",
            ]),
            .heading("Messages are not decrypted"),
            .paragraph("The secret key must be in your keyring, and the message must have been encrypted to it. Reopen the message after entering your passphrase."),
        ]),
        HelpTopic(id: "security", title: "Security notes", symbol: "lock.shield", blocks: [
            .bullets([
                "**Unverified keys** are used for encryption and marked in the compose window. Anyone can publish a key with any address: compare the fingerprint with the recipient through another channel (in person, by phone, on their website), then certify it with `gpg --lsign-key <fingerprint>`.",
                "**Missing Keys** stores the addresses of correspondents with unknown keys unencrypted in `missing-keys.json` in Sigil's App Group container.",
                "**Bcc recipients** stay anonymous, but To and Cc recipients can see how many hidden recipients an encrypted message has.",
                "**Drafts are stored unencrypted**: Mail saves them before Sigil is asked to encrypt.",
                "Keys found only on a keyserver are never ticked automatically and are marked **Keyserver: address not verified**.",
            ]),
        ]),
        HelpTopic(id: "limits", title: "Known limitations", symbol: "exclamationmark.triangle", blocks: [
            .bullets([
                "**Drafts are saved unencrypted.** Mail only calls Sigil when a message is sent, so a draft of an encrypted message is stored in plain text.",
                "**No red badge.** Mail cannot show a red badge for an extension; the red box in the message is used instead.",
                "**Previews of truncated mail** (messages Mail has not downloaded completely) show \"Encrypted message\" until you open them.",
                "**Headers stay readable.** Subject, From, To and Cc are not protected by PGP/MIME.",
                "**Encrypted means everyone.** If one recipient has no key, an encrypted message is not sent.",
            ]),
        ]),
    ]
}
