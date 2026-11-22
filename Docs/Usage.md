# Usage

## The app

The main window has a sidebar:

- **Overview**: a health checklist (helper registered and running, gpg found and its version, pinentry-mac configured, Mail extension enabled, a secret key with an email address) with a short how-to and a **Help** button.
- **My Keys** and **Public Keys** (with a search field).
- **Missing Keys**: see below.

**Settings** (Cmd+,): *General* has the optional gpg path override and the helper's Register and Unregister; *Advanced* has the pinentry check with **Fix...** and the keyserver setup. **Help > Sigil Help** (Cmd+?) opens the in-app help. The About window shows the version, the license and the GnuPG version in use.

## Sending mail

When you write a message, Sigil adds its own sign and encrypt toggles to the compose window.

- **Sign** needs a secret key whose email address matches the From address.
- **Encrypt** needs a usable public key for every recipient (To, Cc and Bcc). If one is missing, Sigil stops the sending instead of sending the message unencrypted.
- Encrypted messages are also encrypted to yourself, so you can read them in your Sent mailbox.
- Bcc recipients are encrypted to as hidden recipients.
- Keys that are not verified yet are used and marked in the compose window: "Key not verified - compare the fingerprint".

Sigil encrypts to every recipient key that is usable for encryption and not expired, revoked or disabled, also when its validity is unknown (for example an imported key you never certified). See [Security and Privacy](Security-and-Privacy.md).

### Several keys for one address

When a recipient has several usable keys, Sigil encrypts to exactly one:

1. the preferred key for that address (**Public Keys > Prefer for <address>**; **Clear preference** undoes it; a preferred key that is no longer usable is ignored);
2. otherwise a verified key over an unverified one;
3. then the key with the newest encryption subkey (else primary key);
4. then the lowest fingerprint.

Sigil never guesses between unverified keys: if an address has more than one usable key and none is verified or preferred, the compose window marks it and sending encrypted is refused with "<address> has several unverified keys. Choose one under Public Keys > Prefer for <address> in the Sigil app." A single unverified key is used and marked.

## Reading mail

- A valid signature gets Mail's normal **signed badge**.
- Encrypted messages are decrypted when you open them; gpg may ask for your passphrase.
- Problems show a **banner** and a **box** at the top of the message text.

Only a top-level `multipart/encrypted` message or a text message that is exactly one armored PGP MESSAGE is decrypted on opening.

### Badge, banner and boxes

Mail's signature badge cannot be changed by an extension, so Sigil marks problems itself.

- **Red box**: the signature is invalid (BAD) or the ciphertext was modified. Do not trust the content. A message that cannot be decrypted shows only a red box instead of the ciphertext.
- **Yellow box**: the signature could not be fully checked: the key is unknown, expired, revoked or distrusted, the signature is expired or cannot be checked, or only part of the message is signed.
- **Signed by a different address**: a good signature by a key that does not carry the From address ("Signed by a different address: <signer> is not the sender <from>") is a problem too: no signed badge, a banner and a yellow box.
- The box is added to the body Sigil hands to Mail; the original content follows unchanged.
- The **banner** and the missing signed badge are the authoritative signal; the box is only an extra. An attacker's HTML could imitate a box, but cannot set Mail's signer state or Sigil's banner.

### Encrypted parts mixed with other content

An encrypted part inside multipart/mixed or alternative, armor with extra text around it, or several encrypted blocks are not decrypted automatically: that is the EFAIL setup, where the surrounding content could send the plaintext out. The message is shown as received, with remote content blocked and the banner "This message contains encrypted parts mixed with other content..." plus **Decrypt anyway**, which shows the decrypted text in Sigil's own plain-text window only, never inside the message.

## Missing Keys

When a complete incoming message is signed with a key that is not in your keyring, the helper notes the key (key ID, fingerprint if the signature carries one, the From address, an email signer user ID if known, first and last seen, and a message count; never the subject or content). The yellow box in Mail then says "Open the Sigil app to fetch this key." The app's **Missing Keys** section lists them and refreshes when the app becomes active.

- **Fetch...** looks the key up with your own gpg and dirmngr configuration; Sigil has no keyserver setting. In order, the helper runs `gpg --locate-external-keys <sender>` (source "auto-key-locate", usually WKD), `gpg --search-keys <sender>` (or the key ID if the sender is unknown; source "keyserver", listed only) and, as a last resort, `gpg --recv-keys <fingerprint or key ID>`. Each command has a 30 s limit. Nothing is written to your keyring while searching, see [Security and Privacy](Security-and-Privacy.md).
- A sheet lists all candidates (deduplicated by fingerprint) with fingerprint, user IDs, creation date, source badges and Expired or Revoked flags. The key that signed the message is marked **Signed this message**. Non-expired, non-revoked keys found through auto-key-locate that signed the message or carry the sender's address are ticked. Keyserver-only keys are never ticked, not even the signing key, and carry the note "Keyserver: address not verified"; expired and revoked ones are dimmed and not ticked. **Select all valid** ticks every valid key with the sender's address. If nothing is found, gpg's own error text is shown, per source, under **Details**.
- **Import** imports each ticked key into your keyring; **Cancel** imports nothing. The entry is removed only when an imported key matches the signature (otherwise the result says "imported, but it doesn't match the signature").
- **Dismiss** hides an entry; it stays dismissed if the key shows up again (count and date still update). **Show dismissed** lists dismissed entries with **Restore** and **Remove**; removing deletes an entry for good (a new message with that key creates a fresh entry). **Remove all dismissed...** removes them all.

## Find Key

**Find Key...** (toolbar, File menu Shift-Cmd-F, Overview) runs the same search for a typed email address, fingerprint or 16-digit key ID; other input is rejected without calling gpg. For an email, valid WKD or locate results with that address are ticked and keyserver-only ones are not; for a fingerprint or key ID the exact match is ticked. Keys already in your keyring are marked "Already imported" and can be imported again to refresh them. No missing-key entry is involved.

## Preferred keys

Under **Public Keys**, **Prefer for <address>** marks the key Sigil uses when that address has several usable keys; **Clear preference** removes the mark. The choice is kept by the helper in `preferred-keys.json` (see [Security and Privacy](Security-and-Privacy.md)).

## Verifying a key

Importing a key does not prove it belongs to the person. Compare the fingerprint with the sender through another channel (in person, by phone, on their website), then certify it locally:

```sh
gpg --lsign-key <fingerprint>
```

A locally signed key counts as verified: Sigil prefers verified keys when a recipient has several, and the yellow box for unknown trust goes away.

## Passphrase prompts

Mail cannot show a terminal prompt, so gpg-agent must use `pinentry-mac` (`brew install pinentry-mac`). The app shows whether `pinentry-program` in `gpg-agent.conf` points at it; **Fix...** (after a confirmation) comments out the old line, adds `pinentry-program <path to pinentry-mac>` and reloads gpg-agent.
