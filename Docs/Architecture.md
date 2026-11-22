# Architecture

Sigil is built on MailKit and has three targets plus a shared Swift package.

| Part | What it is |
|---|---|
| `SigilExtension` | The sandboxed Mail extension. Adds the compose toggles, encodes outgoing and decodes incoming messages, and draws the banner and the warning box. |
| `SigilHelper` | A small unsandboxed LaunchAgent inside the app (`Contents/MacOS/SigilHelper`), registered with `SMAppService` and started by launchd on demand. It is the only part that runs gpg. |
| `Sigil` | The host app (not sandboxed): Overview, keys, Missing Keys, Find Key, settings and help. It registers the helper. |
| `SigilCore` | A local Swift package linked into all three targets: PGP and MIME handling, gpg runner, missing keys, presentation, and the XPC protocol. It has the tests. |

The host app is not sandboxed because macOS refuses to register an unsandboxed agent for a sandboxed app. The Mail extension is sandboxed, which is why it needs the helper to reach gpg.

```
 Apple Mail
     |  MailKit
     v
 SigilExtension (sandboxed) ---XPC--->  SigilHelper (LaunchAgent) ---> gpg / gpg-agent / dirmngr
                                              ^                         (your GnuPG, your keys)
 Sigil app (SwiftUI) -------------XPC---------+
        \                                                  
         `-- App Group container: missing-keys.json, preferred-keys.json
```

## Identity

One build setting, `SIGIL_BUNDLE_PREFIX` in `project.yml` (Debug `org.fuchss.sigil.dev`, Release `org.fuchss.sigil`), drives the three bundle IDs, the App Group (`$(TeamIdentifierPrefix)$(SIGIL_BUNDLE_PREFIX)`), the helper's Mach service name (`$(TeamIdentifierPrefix)$(SIGIL_BUNDLE_PREFIX).helper`) and the LaunchAgent plist name (`<prefix>.helper.plist`, generated from `Helper/helper.plist.template`). Code reads them from the Info.plist keys `SigilBundlePrefix`, `SigilAppGroup`, `SigilMachServiceName` and `SigilHelperPlistName`. The helper accepts clients `<prefix>` and `<prefix>.extension` of the same team only.

## Flows

- **Sending.** Mail calls the extension when a message is sent. The extension asks the helper to resolve every recipient to one usable key, and the helper runs gpg to sign and/or encrypt (always to yourself too, Bcc as hidden recipients), through pipes. The result goes back as PGP/MIME; line endings are LF towards Mail.
- **Reading.** The extension passes the message to the helper, which classifies it (PGP/MIME, inline armor, mixed), runs gpg to decrypt and verify within the caps, and returns the decoded content plus a verdict. The extension sets Mail's signer state, adds the banner, and prepends the warning box to the body.
- **Missing keys.** If a signature's key is unknown, the helper records it in `missing-keys.json`. The app lists these; Fetch and Find Key run gpg in a temporary home through the helper, and Import copies chosen keys into your keyring.
- **Helper registration.** The app registers the LaunchAgent with `SMAppService`; macOS may ask for approval under Login Items.

See [Security and Privacy](Security-and-Privacy.md) for the limits and checks on these flows.

## Layout

See [DEVELOPMENT.md](../DEVELOPMENT.md#project-layout).
