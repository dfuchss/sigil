# Development

## Building

You need Xcode, an Apple ID signed in (for a Team ID) and [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`).

```sh
cp Config/Local.xcconfig.example Config/Local.xcconfig   # set the Team ID; git-ignored
xcodegen generate
xcodebuild -project Sigil.xcodeproj -scheme Sigil -configuration Debug -allowProvisioningUpdates \
  -derivedDataPath build build
```

The `.xcodeproj` is generated and git-ignored. `DEVELOPMENT_TEAM` drives all targets, the App Group and the helper's Mach service name. Version and build come from `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` in `project.yml`.

## Debug builds

Debug builds are "Sigil Dev" with their own identity, so they never clash with the installed release copy: `SIGIL_BUNDLE_PREFIX` in `project.yml` (Debug `org.fuchss.sigil.dev`, Release `org.fuchss.sigil`) drives the bundle IDs, the App Group, the helper's Mach service name and the LaunchAgent plist name (see [Architecture](Docs/Architecture.md)). To test a Debug build in Mail, enable "Sigil Dev OpenPGP" separately in Mail > Settings > Extensions, and keep only one of the two extensions enabled at a time.

Never build while Mail runs: quit Mail first.

To register the Debug helper: open `"build/Build/Products/Debug/Sigil Dev.app"`, then Settings > General > Register (or `open "build/Build/Products/Debug/Sigil Dev.app" --args --register-helper`). Remove the Debug app from Mail afterwards with `pluginkit -r "build/Build/Products/Debug/Sigil Dev.app/Contents/PlugIns/SigilExtension.appex"` and `lsregister -u` on the app.

## Checks and tests

`scripts/check.sh` runs the same checks as CI (`.github/workflows/check.yml`): SigilCore build and tests, shellcheck (if installed) and an unsigned Debug build (skipped while Mail runs).

The tests are in the SigilCore package and need gpg (`brew install gnupg`): `cd SigilCore && swift test`. They use throw-away GnuPG homes, never `~/.gnupg`.

## Debug flags

Debug builds accept these launch flags (used for screenshots):

- `--demo`: fixed, made-up data (`App/DemoData.swift`); the helper is never called.
- `--appearance light|dark`
- `--open overview|mykeys|publickeys|missing|settings|about|help|findkey`

## Scripts

- `scripts/screenshots.sh`: regenerates `Docs/screenshots/` from the Debug build with `--demo` data. Build Debug first; Mail must not be running and the Mac must be unlocked.
- `scripts/make-test-mails.sh`: creates test mails in `TestMails/` (git-ignored). Set `OWNER_EMAIL` to pick your secret key by address.
- `scripts/render-icon.sh`: renders `Design/AppIcon.svg` into `App/Assets.xcassets/AppIcon.appiconset` (needs Inkscape).
- `scripts/install.sh`: builds and installs the Release app, see [Installation](Docs/Installation.md).

## Project layout

- `App/`: the host app (SwiftUI views, models, help text in `HelpContent.swift`, demo data).
- `Extension/`: the Mail extension (compose and security handlers, views).
- `Helper/`: the LaunchAgent (`main.swift`, listener, `helper.plist.template`).
- `Shared/`: code shared by the app and the extension (`HelperClient.swift`).
- `SigilCore/`: the Swift package (PGP, MissingKeys, Presentation, XPC, Models) and its tests.
- `Config/`: xcconfig files; `Design/`: the app icon; `Docs/`: user documentation and screenshots; `scripts/`: tooling.

## Logs

```sh
/usr/bin/log show --info --last 10m --predicate 'subsystem == "org.fuchss.sigil"'
launchctl print gui/$(id -u)/org.fuchss.sigil.helper
```
