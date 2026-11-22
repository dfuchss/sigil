// Prints the CGWindow ID of the frontmost on-screen "Sigil Dev" (Debug build) window at layer 0.
// Usage: winid [title-substring]   (with a filter, only windows whose title contains it match)
import CoreGraphics
import Foundation

let argument = CommandLine.arguments.dropFirst().first ?? ""
let filter: String? = argument.isEmpty ? nil : argument
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
for w in list where (w[kCGWindowOwnerName as String] as? String) == "Sigil Dev" && (w[kCGWindowLayer as String] as? Int) == 0 {
    let bounds = (w[kCGWindowBounds as String] as? NSDictionary).flatMap { CGRect(dictionaryRepresentation: $0 as CFDictionary) }
    guard (bounds?.width ?? 0) > 100 else { continue }
    let title = w[kCGWindowName as String] as? String ?? ""
    if let filter, !title.localizedCaseInsensitiveContains(filter) { continue }
    print(w[kCGWindowNumber as String]!)
    exit(0)
}
exit(1)
