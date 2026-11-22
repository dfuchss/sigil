import Foundation
import os
import SigilCore

private let logger = Logger(subsystem: "org.fuchss.sigil", category: "helper")

/// Logs a fault and exits: the helper must not run with a half-known configuration.
private func fail(_ message: String) -> Never {
    logger.fault("\(message, privacy: .public)")
    FileHandle.standardError.write(Data("SigilHelper: \(message)\n".utf8))
    exit(EXIT_FAILURE)
}

// The Mach service name is expanded from $(TeamIdentifierPrefix) into the embedded Info.plist at build time.
guard let machServiceName = Bundle.main.object(forInfoDictionaryKey: "SigilMachServiceName") as? String,
      !machServiceName.isEmpty, !machServiceName.contains("$(") else {
    fail("SigilMachServiceName is missing from the embedded Info.plist")
}
guard let prefix = SigilXPC.bundlePrefix else {
    fail("SigilBundlePrefix is missing from the embedded Info.plist")
}
guard let teamID = SigilXPC.ownTeamIdentifier(), !teamID.isEmpty else {
    fail("the helper is not signed with a team identifier; cannot build the client requirement")
}
guard machServiceName == SigilXPC.machServiceName(teamID: teamID, prefix: prefix) else {
    fail("SigilMachServiceName \(machServiceName) does not match the signing team \(teamID)")
}

// Temporary key-search homes left behind by a killed helper (older than an hour).
if let gpg = GPGRunner.locateGPG() {
    let removed = KeySearchCleanup.removeStaleHomes(gpgconf: GPGRunner(gpgPath: gpg).gpgconfPath)
    if removed > 0 { logger.info("removed \(removed) stale temporary GnuPG homes") }
}

private let delegate = ListenerDelegate(teamID: teamID, prefix: prefix)
private let listener = NSXPCListener(machServiceName: machServiceName)
listener.delegate = delegate
listener.resume()
logger.info("SigilHelper started, listening on \(machServiceName, privacy: .public)")
RunLoop.main.run()
