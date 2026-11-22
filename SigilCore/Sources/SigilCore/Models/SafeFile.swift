import Foundation

/// File access for Sigil's JSON stores that refuses symbolic links (`O_NOFOLLOW` semantics): a planted link must not
/// make the helper read or overwrite another file.
public enum SafeFile {
    public struct SymlinkRefused: LocalizedError, Equatable {
        public let path: String
        public var errorDescription: String? { "Sigil refuses to use \(path): it is a symbolic link." }
    }

    public static func isSymlink(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
    }

    /// The file's contents; nil when it does not exist. Throws for a symbolic link.
    public static func read(_ url: URL) throws -> Data? {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ELOOP { throw SymlinkRefused(path: url.path) }
            return nil
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        return try handle.readToEnd() ?? Data()
    }

    /// Writes atomically (temporary file, then rename over the path); throws if the path is a symbolic link.
    public static func write(_ data: Data, to url: URL) throws {
        if isSymlink(url) { throw SymlinkRefused(path: url.path) }
        try data.write(to: url, options: [.atomic])
    }
}
