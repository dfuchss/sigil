# Security and privacy

Sigil has no server and no telemetry. Nothing leaves your computer except what your own gpg does when you fetch a key (WKD and keyserver lookups). Decoding a message never touches the network (`--no-auto-key-locate --no-auto-key-retrieve`); only Fetch and Find Key do.

## Trust model and recipient keys

Sigil encrypts to every recipient key that is usable for encryption and not expired, revoked or disabled, also when its validity is unknown (for example an imported key you never certified). To let gpg use them, the encrypt call alone runs with `--trust-model always`, and only when every recipient was already resolved to a full fingerprint. Your gpg configuration is not changed, and signature verification still reports gpg's real validity.

## Unverified keys

Anyone can publish a key with any address. Sigil marks recipients with unverified keys in the compose window ("Key not verified - compare the fingerprint"). Compare the fingerprint with the recipient through another channel (in person, by phone, on their website) and certify it locally with `gpg --lsign-key <fingerprint>`. Certified keys count as verified. Keys found only on a keyserver are never ticked automatically and are marked "Keyserver: address not verified".

## Ambiguous recipients

If an address has more than one usable key and none is verified or preferred, Sigil never guesses: sending encrypted is refused until you choose a key under Public Keys > Prefer for <address>. See [Usage](Usage.md).

## EFAIL behaviour

- Remote content is blocked in messages shown by Sigil.
- Encrypted parts mixed with other content (inside multipart/mixed or alternative, armor with extra text around it, or several encrypted blocks) are not decrypted automatically. **Decrypt anyway** shows the text in Sigil's own plain-text window, never inside the message.
- Only a top-level `multipart/encrypted` message or a text message that is exactly one armored PGP MESSAGE is decrypted on opening.
- Per message the helper handles at most 16 PGP parts or armor blocks, and stops gpg after 20 s (140 s when you entered a passphrase) or when gpg writes more than 64 MB (a compressed message can expand enormously). The result is an error and no plaintext. Inline armor beyond 16 blocks or 2 MB of text only gets the neutral preview.
- The banner and the missing signed badge are the authoritative signal; the warning box is only an extra. Status lines are only read from gpg's status pipe, so a user ID containing status-like text cannot produce a good signature.

## What is stored where

- `missing-keys.json` in the App Group container: key ID, fingerprint, From address, signer email, first and last seen and a count for messages signed with unknown keys. It stores correspondent addresses unencrypted. No subject, content or Message-ID; repeated decodes of the same message count once (hashes are kept in memory only).
- `preferred-keys.json` in the App Group container: your preferred key per address, kept by the helper.
- Helper settings (the gpg path) in `~/Library/Application Support/<prefix>.helper/settings.json`, set only by the app through XPC. An old `gpgPath` value in the App Group defaults is ignored and removed.
- The stores refuse symbolic links.
- Message content is never written to disk: it goes to gpg through pipes.
- Fetching uses a temporary GnuPG home (short path under `/tmp`); see below.

## Fetching keys

Fetch and Find Key never let gpg write into your keyring while searching: everything happens in a temporary GnuPG home with a `gpg.conf` and `dirmngr.conf` that keep only your lookup options (gpg: `keyserver`, `auto-key-locate`, harmless `keyserver-options` and `trust-model`; dirmngr: `keyserver`, `hkp-cacert`, `honor-http-proxy`, `http-proxy`, `use-tor`, `standard-resolver`, `resolver-timeout`). Options such as `keyring`, `homedir` or `load-extension` are dropped. Import exports each ticked fingerprint individually (it must have an email user ID) and imports with `--import-options import-clean,self-sigs-only` into your keyring. The temporary home, with its gpg-agent and dirmngr, is deleted when the sheet closes, and by the helper after five minutes at the latest; homes left behind by a killed helper are removed when it starts (after an hour).

## Bcc key-ID note

To and Cc recipients can see how many hidden (Bcc) recipients an encrypted message has: each adds a key ID 0 (wildcard) entry to the ciphertext, though not who they are.

## Helper caller checks

The helper accepts only the Sigil app and its Mail extension (code signature of the same team, checked per connection). The extension may only list keys, encode and decode; settings, key imports and searches are for the app only. The app and the extension in turn only talk to a helper signed as `<prefix>.helper` by the same team.

## gpg checks

The helper uses the gpg path from Settings if it passes the checks, otherwise the first of `/opt/homebrew/bin/gpg`, `/usr/local/bin/gpg`, `/usr/local/MacGPG2/bin/gpg` that does. A gpg (and the `gpgconf` next to it) must be an absolute path to a regular executable owned by you or root, not group- or world-writable, not in a temporary folder or an app or App Group container. `gpg --version` must report GnuPG 2.2.17 or newer (older versions lack `self-sigs-only`).

## Logging

Logs keep addresses, signer names, gpg diagnostics and error texts private (`log` shows them redacted).

## Drafts

Drafts are stored unencrypted (a MailKit limitation); see [Known limitations](Known-Limitations.md).
