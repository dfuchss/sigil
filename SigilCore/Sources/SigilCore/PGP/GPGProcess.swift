import Foundation

/// A child process started with `posix_spawn`: stdin, stdout, stderr and a separate status pipe as fd 3. Only these
/// four descriptors are inherited (`POSIX_SPAWN_CLOEXEC_DEFAULT`). The fields are the parent's ends.
struct SpawnedChild {
    let pid: pid_t
    let stdin: Int32
    let stdout: Int32
    let stderr: Int32
    let status: Int32

    struct SpawnError: LocalizedError {
        let code: Int32
        var errorDescription: String? { String(cString: strerror(code)) }
    }

    static func spawn(path: String, arguments: [String], environment: [String: String]) throws -> SpawnedChild {
        // (parent end, child end, child fd): the child reads stdin and writes the others.
        var pipes: [(parent: Int32, child: Int32, target: Int32)] = []
        func closeAll() { for p in pipes { close(p.parent); close(p.child) } }
        for target: Int32 in [0, 1, 2, 3] {
            var fds: [Int32] = [0, 0]
            guard pipe(&fds) == 0 else { let code = errno; closeAll(); throw SpawnError(code: code) }
            let (readEnd, writeEnd) = (fds[0], fds[1])
            let (parentEnd, childEnd) = target == 0 ? (writeEnd, readEnd) : (readEnd, writeEnd)
            // Move the child's end above the target range, so dup2 never maps a descriptor onto itself (which would
            // keep its close-on-exec flag); both ends stay close-on-exec in the parent.
            let movedChild = fcntl(childEnd, F_DUPFD_CLOEXEC, 10)
            close(childEnd)
            _ = fcntl(parentEnd, F_SETFD, FD_CLOEXEC)
            pipes.append((parentEnd, movedChild, target))
            guard movedChild >= 0 else { let code = errno; closeAll(); throw SpawnError(code: code) }
        }

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        for p in pipes { posix_spawn_file_actions_adddup2(&actions, p.child, p.target) }

        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        var emptyMask = sigset_t()
        var defaultSignals: sigset_t = (1 << (SIGPIPE - 1))
        posix_spawnattr_setsigmask(&attributes, &emptyMask)
        posix_spawnattr_setsigdefault(&attributes, &defaultSignals)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF))

        let argv: [UnsafeMutablePointer<CChar>?] = ([path] + arguments).map { strdup($0) } + [nil]
        let envp: [UnsafeMutablePointer<CChar>?] = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            for pointer in argv { free(pointer) }
            for pointer in envp { free(pointer) }
        }
        var pid: pid_t = 0
        let result = posix_spawn(&pid, path, &actions, &attributes, argv, envp)
        for p in pipes { close(p.child) }
        guard result == 0 else {
            for p in pipes { close(p.parent) }
            throw SpawnError(code: result)
        }
        // Writing to a pipe whose reader exited must fail with EPIPE instead of raising SIGPIPE.
        _ = fcntl(pipes[0].parent, F_SETNOSIGPIPE, 1)
        return SpawnedChild(pid: pid, stdin: pipes[0].parent, stdout: pipes[1].parent, stderr: pipes[2].parent,
                            status: pipes[3].parent)
    }
}

enum CappedRead {
    /// Reads until EOF or until more than `limit` bytes arrived (then stops at once, `exceeded == true`); closes `fd`.
    static func read(fd: Int32, limit: Int) -> (Data, exceeded: Bool) {
        defer { close(fd) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if count > 0 {
                if data.count + count > limit {
                    data.append(contentsOf: buffer[0..<(limit - data.count)])
                    return (data, true)
                }
                data.append(contentsOf: buffer[0..<count])
            } else if count == 0 {
                return (data, false)
            } else if errno != EINTR {
                return (data, false)
            }
        }
    }

    /// Writes all of `data`, giving up when the reader is gone.
    static func writeAll(_ data: Data, to fd: Int32) {
        data.withUnsafeBytes { raw in
            guard var pointer = raw.baseAddress else { return }
            var remaining = raw.count
            while remaining > 0 {
                let written = Darwin.write(fd, pointer, remaining)
                if written > 0 {
                    pointer += written
                    remaining -= written
                } else if written < 0 && errno == EINTR {
                    continue
                } else {
                    return
                }
            }
        }
    }
}

final class OverflowFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set() { lock.lock(); value = true; lock.unlock() }
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
}

/// Cancels gpg runs: `cancel()` kills every gpg currently running under it, and every later run fails at once with
/// `GPGError.cancelled`. The helper keeps one per XPC connection and cancels it when the connection goes away.
public final class GPGCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var running: Set<pid_t> = []

    public init() {}

    public var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }

    public func cancel() {
        lock.lock()
        cancelled = true
        let pids = running
        lock.unlock()
        for pid in pids { kill(pid, SIGKILL) }
    }

    /// False when already cancelled (the caller then kills the process itself).
    func register(_ pid: pid_t) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !cancelled else { return false }
        running.insert(pid)
        return true
    }

    /// Called before the process is reaped, so `cancel` never signals a recycled pid.
    func unregister(_ pid: pid_t) {
        lock.lock(); running.remove(pid); lock.unlock()
    }
}

/// The minimum GnuPG version: 2.2.8 enforces integrity protection (no decryption without MDC/AEAD) and fixed the
/// file-name injection into status output (CVE-2018-12020); 2.2.17 added the `self-sigs-only` import option that
/// key imports rely on against signature flooding.
public enum GPGVersion {
    public static let minimum = [2, 2, 17]

    /// The version numbers of a `gpg --version` first line such as "gpg (GnuPG) 2.5.24" (suffixes like "-beta" are
    /// ignored); nil when it is not a GnuPG line.
    public static func parse(_ firstLine: String, program: String = "gpg") -> [Int]? {
        let prefix = "\(program) (GnuPG) "
        guard firstLine.hasPrefix(prefix) else { return nil }
        let token = firstLine.dropFirst(prefix.count).split(separator: " ").first.map(String.init) ?? ""
        let numbers = token.split(separator: ".").map { part in Int(part.prefix { $0.isNumber }) }
        guard !numbers.isEmpty, numbers.allSatisfy({ $0 != nil }) else { return nil }
        return numbers.compactMap { $0 }
    }

    public static func isSupported(_ version: [Int]) -> Bool {
        for index in 0..<minimum.count {
            let part = index < version.count ? version[index] : 0
            if part != minimum[index] { return part > minimum[index] }
        }
        return true
    }

    /// Throws `GPGError.unsupportedVersion` unless the line is GnuPG 2.2.17 or newer.
    public static func requireSupported(_ firstLine: String, program: String = "gpg") throws {
        guard let version = parse(firstLine, program: program) else {
            throw GPGError.unsupportedVersion(firstLine.isEmpty ? "no version" : String(firstLine.prefix(80)))
        }
        guard isSupported(version) else {
            throw GPGError.unsupportedVersion(version.map(String.init).joined(separator: "."))
        }
    }
}

/// Checks a gpg path before the helper runs it (the helper is unsandboxed, so a planted binary would run with the
/// user's full rights).
public enum GPGPathValidator {
    public struct Rejected: LocalizedError, Equatable {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// Directories a sandboxed process (or another user) can write to; no gpg may live there.
    public static var defaultForbiddenPrefixes: [String] {
        let home = NSHomeDirectory()
        return ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/var/folders/", "/private/var/folders/",
                home + "/Library/Group Containers/", home + "/Library/Containers/"]
    }

    /// Validates `path` and the `gpgconf` next to it and returns the gpg URL: an absolute path to an existing regular
    /// executable file (symlinks are resolved and both paths checked), not inside a forbidden directory, owned by the
    /// user or root, not group- or world-writable; `--version` must report GnuPG 2.2.17 or newer.
    public static func validate(_ path: String, forbiddenPrefixes: [String]? = nil) throws -> URL {
        let forbidden = forbiddenPrefixes ?? defaultForbiddenPrefixes
        try checkFile(path, forbidden: forbidden)
        let gpgconf = URL(fileURLWithPath: path).deletingLastPathComponent().appendingPathComponent("gpgconf").path
        try checkFile(gpgconf, forbidden: forbidden)
        try GPGVersion.requireSupported(try firstOutputLine(path), program: "gpg")
        guard GPGVersion.parse(try firstOutputLine(gpgconf), program: "gpgconf") != nil else {
            throw Rejected(message: "\(gpgconf) is not GnuPG's gpgconf")
        }
        return URL(fileURLWithPath: path)
    }

    static func checkFile(_ path: String, forbidden: [String]) throws {
        guard path.hasPrefix("/") else { throw Rejected(message: "\(path) is not an absolute path") }
        guard !path.split(separator: "/").contains(where: { $0 == ".." || $0 == "." }) else {
            throw Rejected(message: "\(path) contains . or .. components")
        }
        guard let resolvedPointer = realpath(path, nil) else { throw Rejected(message: "\(path) does not exist") }
        let resolved = String(cString: resolvedPointer)
        free(resolvedPointer)
        for candidate in [path, resolved] {
            if let prefix = forbidden.first(where: { candidate.hasPrefix($0) }) {
                throw Rejected(message: "\(path) lies in \(prefix), where gpg must not live")
            }
        }
        var info = stat()
        guard stat(resolved, &info) == 0 else { throw Rejected(message: "\(path) does not exist") }
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw Rejected(message: "\(path) is not a regular file") }
        guard info.st_uid == getuid() || info.st_uid == 0 else {
            throw Rejected(message: "\(path) is owned by another user")
        }
        guard (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 else {
            throw Rejected(message: "\(path) is writable by group or others")
        }
        guard access(resolved, X_OK) == 0 else { throw Rejected(message: "\(path) is not executable") }
    }

    /// The first stdout line of `<path> --version` (10 s at most).
    static func firstOutputLine(_ path: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--version"]
        process.environment = ["LC_ALL": "C", "PATH": "/usr/bin:/bin"]
        let outPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        do { try process.run() } catch { throw Rejected(message: "\(path) could not be started") }
        // A duplicate descriptor: CappedRead closes it, the FileHandle closes its own.
        let readFD = dup(outPipe.fileHandleForReading.fileDescriptor)
        let box = DataBox()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            box.set(CappedRead.read(fd: readFD, limit: 64 * 1024).0)
            done.signal()
        }
        if exited.wait(timeout: .now() + 10) == .timedOut {
            kill(process.processIdentifier, SIGKILL)
            throw Rejected(message: "\(path) --version did not finish")
        }
        _ = done.wait(timeout: .now() + 2)
        return Bytes.string([UInt8](box.get())).split(separator: "\n").first.map(String.init) ?? ""
    }
}
