import Foundation

/// Why bytes are not a JSON document this SDK will read.
enum JSONParseFailure: Error, Sendable, Equatable {
    /// Not well-formed RFC 8259 JSON in well-formed UTF-8.
    case notJSON
    /// Well-formed, but one object names a member twice.
    case duplicateMember
}

/// A strict RFC 8259 parser, written for the ID-token path rather than taken
/// from `JSONDecoder`, because the verifier needs two things a general decoder
/// does not promise (docs/mobile-SDKs.md §5.2, settled 2026-09-25):
///
/// - **A member named twice is refused.** One parser keeps the first and
///   another the last, so the same bytes would name two people. The refusal
///   is reported only for a document that is otherwise well-formed — the
///   order `reference-verify.mjs` checks in (`JSON.parse`, then the duplicate
///   scan) — so a vector is refused for the same reason here. "Twice" is by
///   the name's code points, as the reference (JavaScript strings) and the
///   Android SDK compare them — **not** by Swift's `String` equality, which
///   is canonical equivalence. Two names that differ in their code points but
///   are canonically equivalent (`é` and `e` + U+0301) are two members, and
///   the document is accepted as the reference accepts it; but a Swift
///   dictionary cannot hold both, so **neither is kept** rather than one
///   chosen — a member whose name is ambiguous here is not readable at all.
///   No name the verifier reads (`alg`, `kid`, `crit`, `iss`, `aud`, `sub`,
///   `exp`, `iat`, `nonce`, `at_hash`) has a canonically equivalent second
///   spelling, so no verdict turns on it. (Pending a vector in §5.2.)
/// - **What does not parse is a refusal, never a crash** — with the reason
///   (`notJSON`) kept apart from the duplicate.
///
/// Otherwise it is `JSON.parse`, as the Android SDK's parser is: well-formed
/// UTF-8 only (no replacement characters), no byte-order mark, no comments or
/// trailing commas or leading zeros, no lone surrogates, no trailing content,
/// and at most `maximumDepth` levels of nesting.
struct StrictJSON {
    /// The Android SDK's limit. Nothing this SDK reads nests more than four.
    static let maximumDepth = 64

    private let scalars: [Unicode.Scalar]
    private var index = 0
    private var sawDuplicate = false

    private init(_ scalars: [Unicode.Scalar]) {
        self.scalars = scalars
    }

    /// Parses one JSON document, of any type.
    static func parse(_ data: Data) throws -> JSONValue {
        guard let scalars = decodeUTF8(data) else { throw JSONParseFailure.notJSON }
        var parser = StrictJSON(scalars)
        let value = try parser.document()
        if parser.sawDuplicate { throw JSONParseFailure.duplicateMember }
        return value
    }

    /// Well-formed UTF-8 as scalars, or `nil`. The standard library's decoder
    /// refuses overlong forms, surrogates and anything past U+10FFFF.
    private static func decodeUTF8(_ data: Data) -> [Unicode.Scalar]? {
        var scalars: [Unicode.Scalar] = []
        scalars.reserveCapacity(data.count)
        var iterator = data.makeIterator()
        var decoder = UTF8()
        while true {
            switch decoder.decode(&iterator) {
            case .scalarValue(let scalar): scalars.append(scalar)
            case .emptyInput: return scalars
            case .error: return nil
            }
        }
    }

    // MARK: - The grammar

    private mutating func document() throws -> JSONValue {
        skipWhitespace()
        let value = try self.value(depth: 0)
        skipWhitespace()
        guard index == scalars.count else { throw JSONParseFailure.notJSON }
        return value
    }

    private var current: Unicode.Scalar? { index < scalars.count ? scalars[index] : nil }

    private mutating func skipWhitespace() {
        while let scalar = current, scalar == " " || scalar == "\t" || scalar == "\n" || scalar == "\r" {
            index += 1
        }
    }

    private mutating func expect(_ scalar: Unicode.Scalar) throws {
        guard current == scalar else { throw JSONParseFailure.notJSON }
        index += 1
    }

    private mutating func value(depth: Int) throws -> JSONValue {
        guard let scalar = current else { throw JSONParseFailure.notJSON }
        switch scalar {
        case "{": return try object(depth: depth + 1)
        case "[": return try array(depth: depth + 1)
        case "\"": return .string(try string())
        case "t": try literal("true"); return .bool(true)
        case "f": try literal("false"); return .bool(false)
        case "n": try literal("null"); return .null
        case "-", "0"..."9": return .number(try number())
        default: throw JSONParseFailure.notJSON
        }
    }

    private mutating func literal(_ word: String) throws {
        for scalar in word.unicodeScalars { try expect(scalar) }
    }

    private mutating func object(depth: Int) throws -> JSONValue {
        guard depth <= Self.maximumDepth else { throw JSONParseFailure.notJSON }
        try expect("{")
        var members: [String: JSONValue] = [:]
        // Names by their code points, to find a true duplicate; and names
        // that are canonically equivalent to another member's, kept out.
        var seen = Set<[UInt32]>()
        var ambiguous = Set<String>()
        skipWhitespace()
        if current == "}" {
            index += 1
            return .object(members)
        }
        while true {
            skipWhitespace()
            guard current == "\"" else { throw JSONParseFailure.notJSON }
            let name = try string()
            skipWhitespace()
            try expect(":")
            skipWhitespace()
            let member = try value(depth: depth)
            // Recorded, not thrown: a syntax error later in the document is
            // the reason that wins, as it does in the reference.
            if !seen.insert(name.unicodeScalars.map(\.value)).inserted {
                sawDuplicate = true
            } else if members[name] != nil || ambiguous.contains(name) {
                members[name] = nil
                ambiguous.insert(name)
            } else {
                members[name] = member
            }
            skipWhitespace()
            guard let next = current else { throw JSONParseFailure.notJSON }
            index += 1
            if next == "}" { return .object(members) }
            guard next == "," else { throw JSONParseFailure.notJSON }
        }
    }

    private mutating func array(depth: Int) throws -> JSONValue {
        guard depth <= Self.maximumDepth else { throw JSONParseFailure.notJSON }
        try expect("[")
        var items: [JSONValue] = []
        skipWhitespace()
        if current == "]" {
            index += 1
            return .array(items)
        }
        while true {
            skipWhitespace()
            items.append(try value(depth: depth))
            skipWhitespace()
            guard let next = current else { throw JSONParseFailure.notJSON }
            index += 1
            if next == "]" { return .array(items) }
            guard next == "," else { throw JSONParseFailure.notJSON }
        }
    }

    private mutating func string() throws -> String {
        try expect("\"")
        var out = String.UnicodeScalarView()
        while true {
            guard let scalar = current else { throw JSONParseFailure.notJSON }
            index += 1
            switch scalar {
            case "\"":
                return String(out)
            case "\\":
                guard let escape = current else { throw JSONParseFailure.notJSON }
                index += 1
                switch escape {
                case "\"": out.append("\"")
                case "\\": out.append("\\")
                case "/": out.append("/")
                case "b": out.append("\u{08}")
                case "f": out.append("\u{0C}")
                case "n": out.append("\n")
                case "r": out.append("\r")
                case "t": out.append("\t")
                case "u": out.append(try unicodeEscape())
                default: throw JSONParseFailure.notJSON
                }
            case "\u{00}"..."\u{1F}":
                // A control character must be escaped.
                throw JSONParseFailure.notJSON
            default:
                out.append(scalar)
            }
        }
    }

    /// After `\u`: four hex digits, and for a high surrogate the `\uXXXX` of
    /// its low half. A lone surrogate is not a scalar and is refused.
    private mutating func unicodeEscape() throws -> Unicode.Scalar {
        let first = try hex4()
        if (0xDC00...0xDFFF).contains(first) { throw JSONParseFailure.notJSON }
        if (0xD800...0xDBFF).contains(first) {
            try expect("\\")
            try expect("u")
            let second = try hex4()
            guard (0xDC00...0xDFFF).contains(second) else { throw JSONParseFailure.notJSON }
            let combined = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            guard let scalar = Unicode.Scalar(combined) else { throw JSONParseFailure.notJSON }
            return scalar
        }
        guard let scalar = Unicode.Scalar(first) else { throw JSONParseFailure.notJSON }
        return scalar
    }

    private mutating func hex4() throws -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 {
            guard let scalar = current, let digit = Self.hexValue(scalar) else { throw JSONParseFailure.notJSON }
            index += 1
            value = value << 4 | digit
        }
        return value
    }

    private static func hexValue(_ scalar: Unicode.Scalar) -> UInt32? {
        switch scalar {
        case "0"..."9": return scalar.value - 0x30
        case "a"..."f": return scalar.value - 0x61 + 10
        case "A"..."F": return scalar.value - 0x41 + 10
        default: return nil
        }
    }

    /// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`
    private mutating func number() throws -> Double {
        let start = index
        if current == "-" { index += 1 }
        guard let lead = current else { throw JSONParseFailure.notJSON }
        if lead == "0" {
            index += 1
        } else if ("1"..."9").contains(lead) {
            skipDigits()
        } else {
            throw JSONParseFailure.notJSON
        }
        if current == "." {
            index += 1
            guard requireDigit() else { throw JSONParseFailure.notJSON }
        }
        if current == "e" || current == "E" {
            index += 1
            if current == "+" || current == "-" { index += 1 }
            guard requireDigit() else { throw JSONParseFailure.notJSON }
        }
        var text = String.UnicodeScalarView()
        text.append(contentsOf: scalars[start..<index])
        guard let value = Double(String(text)) else { throw JSONParseFailure.notJSON }
        return value
    }

    private mutating func skipDigits() {
        while let scalar = current, ("0"..."9").contains(scalar) { index += 1 }
    }

    /// At least one digit, consumed with any that follow.
    private mutating func requireDigit() -> Bool {
        guard let scalar = current, ("0"..."9").contains(scalar) else { return false }
        skipDigits()
        return true
    }
}
