import Foundation

/// Low-level byte helpers shared by the MIME code. All MIME processing works on raw bytes.
enum Bytes {
    static let cr: UInt8 = 0x0D
    static let lf: UInt8 = 0x0A
    static let sp: UInt8 = 0x20
    static let tab: UInt8 = 0x09
    static let crlf: [UInt8] = [0x0D, 0x0A]

    /// Index of the next LF in `b[from..<end]`, or `end`.
    @inline(__always)
    static func nextLF(_ b: [UInt8], from: Int, end: Int) -> Int {
        var i = from
        while i < end {
            if b[i] == lf { return i }
            i += 1
        }
        return end
    }

    /// Splits `b[start..<end]` into lines. Each element is (contentStart, contentEnd, nextLineStart),
    /// where content excludes the CRLF / LF terminator.
    static func lines(_ b: [UInt8], _ start: Int, _ end: Int) -> [(Int, Int, Int)] {
        var result: [(Int, Int, Int)] = []
        var i = start
        while i < end {
            let lfIndex = nextLF(b, from: i, end: end)
            var ce = lfIndex
            if lfIndex < end, ce > i, b[ce - 1] == cr { ce -= 1 }
            let next = lfIndex < end ? lfIndex + 1 : end
            result.append((i, ce, next))
            i = next
        }
        return result
    }

    static func hasPrefix(_ b: [UInt8], at index: Int, end: Int, _ prefix: [UInt8]) -> Bool {
        guard index + prefix.count <= end else { return false }
        for k in 0..<prefix.count where b[index + k] != prefix[k] { return false }
        return true
    }

    static func hasPrefixCaseInsensitive(_ b: [UInt8], at index: Int, end: Int, _ prefix: [UInt8]) -> Bool {
        guard index + prefix.count <= end else { return false }
        for k in 0..<prefix.count where lower(b[index + k]) != lower(prefix[k]) { return false }
        return true
    }

    @inline(__always)
    static func lower(_ c: UInt8) -> UInt8 {
        (c >= 0x41 && c <= 0x5A) ? c + 0x20 : c
    }

    /// Case-insensitive substring search.
    static func containsCaseInsensitive(_ b: [UInt8], _ needle: String) -> Bool {
        let n = Array(needle.utf8).map(lower)
        guard !n.isEmpty, b.count >= n.count else { return n.isEmpty }
        let first = n[0]
        var i = 0
        let last = b.count - n.count
        while i <= last {
            if lower(b[i]) == first {
                var ok = true
                for k in 1..<n.count where lower(b[i + k]) != n[k] { ok = false; break }
                if ok { return true }
            }
            i += 1
        }
        return false
    }

    /// Decodes bytes as UTF-8, falling back to ISO-8859-1 (which never fails).
    static func string(_ bytes: some Collection<UInt8>) -> String {
        if let s = String(bytes: Array(bytes), encoding: .utf8) { return s }
        return String(bytes.map { Character(Unicode.Scalar($0)) })
    }

    /// Converts all line endings (bare LF, CRLF) to CRLF. Bare CRs are left untouched.
    static func normalizeCRLF(_ b: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(b.count + b.count / 32)
        var i = 0
        while i < b.count {
            let c = b[i]
            if c == lf {
                if i == 0 || b[i - 1] != cr { out.append(cr) }
                out.append(lf)
            } else {
                out.append(c)
            }
            i += 1
        }
        return out
    }

    /// Replaces the given ranges (must not overlap) in `source` with replacement bytes.
    static func splice(_ source: [UInt8], _ replacements: [(Range<Int>, [UInt8])]) -> [UInt8] {
        let sorted = replacements.sorted { $0.0.lowerBound < $1.0.lowerBound }
        var out: [UInt8] = []
        out.reserveCapacity(source.count)
        var cursor = 0
        for (range, data) in sorted {
            guard range.lowerBound >= cursor else { continue } // overlapping: ignore
            out.append(contentsOf: source[cursor..<range.lowerBound])
            out.append(contentsOf: data)
            cursor = range.upperBound
        }
        out.append(contentsOf: source[cursor...])
        return out
    }

    static func isSevenBitClean(_ b: some Collection<UInt8>) -> Bool {
        for c in b where c >= 0x80 || c == 0 { return false }
        return true
    }
}

public enum LineEndings {
    /// Converts bare LF line endings to CRLF (RFC 3156 canonical form).
    public static func toCRLF(_ data: Data) -> Data {
        Data(Bytes.normalizeCRLF([UInt8](data)))
    }

    /// Converts CRLF line endings to LF (Mail's internal form); bare CRs are kept.
    public static func toLF(_ data: Data) -> Data {
        var result = Data(capacity: data.count)
        var previousCR = false
        for byte in data {
            if previousCR && byte != 0x0A { result.append(0x0D) }
            previousCR = (byte == 0x0D)
            if !previousCR { result.append(byte) }
        }
        if previousCR { result.append(0x0D) }
        return result
    }

    /// True when the first 64 KB contain no CR, i.e. the data uses LF line endings like Mail's.
    public static func usesBareLF(_ data: Data) -> Bool {
        !data.prefix(64 * 1024).contains(0x0D)
    }
}
