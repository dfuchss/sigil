# Installation

Sigil is built from source; there are no prebuilt downloads yet, because they would need a paid Developer ID and notarization. A free Apple ID (Personal Team) is enough to sign the build.

## Requirements

- macOS 14 or newer.
- Xcode, with the command line tools pointing at it: `sudo xcode-select -s /Applications/Xcode.app`.
- An Apple ID signed into Xcode (Settings > Accounts), to obtain a Team ID.
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`.
- GnuPG 2.2.17 or newer and pinentry-mac: `brew install gnupg pinentry-mac`.
- A secret key with an email address. If you have none: `gpg --quick-gen-key "Your Name <you@example.org>"`.

## Install

1. Copy `Config/Local.xcconfig.example` to `Config/Local.xcconfig` and set your Team ID (the file is git-ignored). The Team ID drives all targets, the App Group and the helper's Mach service name.
2. Quit Mail.
3. Run `scripts/install.sh`.
4. Enable "Sigil OpenPGP" in Mail > Settings > Extensions.
5. If the app reports "Requires approval", open System Settings > General > Login Items & Extensions and allow Sigil ("Allow in the Background").

`scripts/install.sh` builds the Release app into `build/release`, verifies its signature, quits Sigil, copies it to `/Applications/Sigil.app`, registers only that copy with Launch Services and PlugInKit, re-registers the helper (`open /Applications/Sigil.app --args --register-helper`) and checks with `launchctl print` and `lsof` that the helper runs from `/Applications`. It refuses to run while Mail is open and never calls `sfltool`.

Unsigned builds (`CODE_SIGNING_ALLOWED=NO`) work for compile checks only: Mail does not load an unsigned extension, and the helper refuses to start without a team signature.

## Check the first run

Open Sigil. The **Overview** is a health checklist; every item should be green:

- the helper is registered and running (**Settings > General > Register** if not);
- gpg is found, with its version;
- pinentry-mac is configured (**Settings > Advanced > Fix...** if not);
- the Mail extension is enabled;
- a secret key with an email address exists;
- a keyserver is configured in gpg (optional, see below).

The Overview also has a short how-to and a **Help** button; **Help > Sigil Help** (Cmd+?) opens the in-app help.

## Keyserver setup

Sigil leaves key fetching to your gpg configuration. Homebrew GnuPG ships without a keyserver, so `gpg --search-keys` fails with "No keyserver available" and only WKD works. The Overview ("Keyserver configured in gpg"), **Settings > Advanced** and the key search sheet offer **Set up keys.openpgp.org...**: after a confirmation it appends `keyserver hkps://keys.openpgp.org` to `<homedir>/dirmngr.conf` (it comments out a `keyserver ... none` line and creates the file if needed) and runs `gpgconf --reload dirmngr`. keys.openpgp.org only serves keys with verified email addresses.

## gpg path

Settings > General has an optional gpg path override. It is validated and stored by the helper in its own settings (not in the App Group); empty means the Homebrew locations. See [Security and Privacy](Security-and-Privacy.md) for the checks.

## Update

Sigil does not update itself. Pull the newer version, quit Mail and run `scripts/install.sh` again. After an update that adds a capability, check in Mail > Settings > Extensions that Sigil is still ticked and lists the new permission.

If you move an existing install, a logout or reboot may be needed, because launchd caches the old path of the helper.

## Uninstall

1. In Sigil, open **Settings > General** and press **Unregister** (this removes the helper's LaunchAgent).
2. Quit Mail and Sigil, and untick the extension in Mail > Settings > Extensions.
3. Delete `/Applications/Sigil.app`.
4. Optionally delete the data Sigil keeps: the App Group container (`missing-keys.json`, `preferred-keys.json`) and `~/Library/Application Support/org.fuchss.sigil.helper/` (the helper's settings). Your GnuPG keyring is never touched by removing Sigil.
