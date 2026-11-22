# Troubleshooting

## The helper is not running

Open the Overview. If the helper is not registered or not answering, use **Settings > General > Register**, approve it in System Settings > General > Login Items & Extensions if asked, then press Refresh. If gpg is reported as not found, set its path in **Settings > General**.

Headless: `open "/Applications/Sigil.app" --args --register-helper` registers the helper and logs the status. Inspect it with `launchctl print gui/$(id -u)/org.fuchss.sigil.helper`.

The host app is not sandboxed, because macOS refuses to register an unsandboxed agent for a sandboxed app ("SMAppService target executable must be sandboxed because the app is sandboxed"). If the app was ever registered while it was still sandboxed, the Background Items database may keep that state and reject the registration with "Operation not permitted"; `sfltool resetbtm` followed by a reboot clears it, but it resets the approvals of all login items, so use it only as a last resort.

## Mail does not use the extension

Quit Mail completely (Cmd+Q) and open it again, then check Mail > Settings > Extensions that "Sigil OpenPGP" is ticked. After an update, check that it is still ticked and lists the new permission. Mail and PlugInKit cache extensions: running `scripts/install.sh` again re-registers only `/Applications/Sigil.app`. A Debug build ("Sigil Dev OpenPGP") is a separate extension; keep only one of the two enabled.

## The app was moved

After moving an existing install, a logout or reboot may be needed, because launchd caches the old path of the helper.

## Finding keys fails / No keyserver available

- **No keyserver available:** gpg has no keyserver configured, so Find Key and Missing Keys only work via WKD. Use **Set up keys.openpgp.org...** in the Overview, **Settings > Advanced** or the search sheet; see [Installation](Installation.md).
- **Domain does not publish keys via WKD:** the sender's domain has no Web Key Directory. Try the keyserver, or ask the sender for their key.
- **The keyserver has no key for this address:** the owner has not uploaded or verified a key. Search by fingerprint, or ask the sender.
- **Network error:** check your connection and proxy settings, then search again. The sheet's **Details** show gpg's own message.

## Passphrase prompts

- No prompt appears: gpg-agent probably does not use pinentry-mac. Use **Settings > Advanced > Fix...**.
- You are asked again and again: gpg-agent keeps the passphrase only for a while (`default-cache-ttl` in gpg-agent.conf).
- To forget a cached passphrase, run `gpgconf --kill gpg-agent`.

## Messages are not decrypted

The secret key must be in your keyring, and the message must have been encrypted to it. Reopen the message after entering your passphrase. A message with encrypted parts mixed with other content is deliberately not decrypted automatically; use **Decrypt anyway**.

## The app icon looks wrong

macOS caches icons. After an update, relaunch the app, or restart the Dock and Finder (`killall Dock Finder`).

## Logs

```sh
/usr/bin/log show --info --last 10m --predicate 'subsystem == "org.fuchss.sigil"'
```

Addresses, signer names and gpg diagnostics are redacted in the log.
