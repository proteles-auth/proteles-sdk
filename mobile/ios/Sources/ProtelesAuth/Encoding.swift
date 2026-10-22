import Foundation

/// Base64url (RFC 4648 §5) without padding, as JWS and PKCE use it.
enum Base64URL {
    static func encode(_ data: Data) -> String {
        var text = data.base64EncodedString()
        text = text.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while text.hasSuffix("=") { text.removeLast() }
        return text
    }

    /// Strict decoding: the base64url alphabet only, no padding (§5.2 rule 6),
    /// and the canonical spelling only — a final character whose unused bits
    /// are not zero is a second spelling of the same bytes, and is refused.
    static func decode(_ text: some StringProtocol) -> Data? {
        let bytes = Array(text.utf8)
        var standard = [UInt8]()
        standard.reserveCapacity(bytes.count + 3)
        for byte in bytes {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"):
                standard.append(byte)
            case UInt8(ascii: "-"):
                standard.append(UInt8(ascii: "+"))
            case UInt8(ascii: "_"):
                standard.append(UInt8(ascii: "/"))
            default:
                return nil
            }
        }
        if bytes.count % 4 == 1 { return nil }
        standard.append(contentsOf: repeatElement(UInt8(ascii: "="), count: (4 - bytes.count % 4) % 4))
        guard let data = Data(base64Encoded: Data(standard)) else { return nil }
        guard encode(data).utf8.elementsEqual(bytes) else { return nil }
        return data
    }
}

/// `application/x-www-form-urlencoded`, for request bodies and query strings.
enum FormEncoding {
    /// Every byte outside RFC 3986's unreserved set is percent-encoded, so a
    /// `+`, `&`, `=` or space in a value can never be read as syntax — whatever
    /// decoder the server uses.
    static func percentEncode(_ value: String) -> String {
        var out = ""
        out.reserveCapacity(value.utf8.count)
        for byte in value.utf8 {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"),
                 UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "~"):
                out.unicodeScalars.append(Unicode.Scalar(byte))
            default:
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }

    static func encode(_ pairs: [(String, String)]) -> String {
        pairs.map { "\(percentEncode($0.0))=\(percentEncode($0.1))" }.joined(separator: "&")
    }

    /// Parses a query string (without the `?`), decoding `+` as a space and
    /// percent-escapes as UTF-8, keeping repeated names so a caller can refuse
    /// them — or `nil` when any escape is malformed or decodes to bytes that
    /// are not UTF-8. A callback is read with this: dropping the pair that
    /// does not decode would let a second `state`, `iss` or `code` carrying a
    /// bad escape slip past the "exactly once" checks.
    static func decodeExactly(_ query: String) -> [(name: String, value: String)]? {
        guard !query.isEmpty else { return [] }
        var fields: [(name: String, value: String)] = []
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let name = unescape(parts[0]), let value = parts.count > 1 ? unescape(parts[1]) : "" else { return nil }
            fields.append((name, value))
        }
        return fields
    }

    /// `decodeExactly`, dropping a pair whose escapes do not decode. For
    /// diagnostics and tests only — never for a response the SDK acts on.
    static func decode(_ query: String) -> [(name: String, value: String)] {
        guard !query.isEmpty else { return [] }
        return query.split(separator: "&", omittingEmptySubsequences: true).compactMap { pair in
            decodeExactly(String(pair))?.first
        }
    }

    private static func unescape(_ text: Substring) -> String? {
        text.replacingOccurrences(of: "+", with: " ").removingPercentEncoding
    }
}

/// A JSON value, with numbers and booleans kept apart — `true` is not the
/// number 1, and a claim that must be a number is checked as one.
public enum JSONValue: Sendable, Hashable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case null
    case array([JSONValue])
    case object([String: JSONValue])

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var numberValue: Double? {
        if case .number(let value) = self { return value }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    /// Parses `data` as a JSON document; `nil` when it is not one — including
    /// one that names a member twice (`StrictJSON`), whose meaning depends on
    /// which parser reads it. Everything the SDK receives is read this way:
    /// discovery, the key set, token responses and ID tokens.
    static func parse(_ data: Data) -> JSONValue? {
        try? StrictJSON.parse(data)
    }

    /// Parses `data` as a JSON object; `nil` when it is anything else.
    static func parseObject(_ data: Data) -> [String: JSONValue]? {
        parse(data)?.objectValue
    }

    /// Parses `data` as a JSON object, saying why when it is not one: a
    /// document naming a member twice is `.duplicateMember`; anything else
    /// that is not an object — not JSON, or JSON of another type — is
    /// `.notJSON`, as the Android SDK reads it.
    static func parseStrictObject(_ data: Data) throws(JSONParseFailure) -> [String: JSONValue] {
        let value: JSONValue
        do {
            value = try StrictJSON.parse(data)
        } catch let failure as JSONParseFailure {
            throw failure
        } catch {
            throw .notJSON
        }
        guard let object = value.objectValue else { throw .notJSON }
        return object
    }
}

extension JSONValue: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "not a JSON value")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .null: try container.encodeNil()
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

/// Byte-for-byte string equality. Swift's `==` compares by Unicode canonical
/// equivalence, so two different byte sequences can be "equal"; an issuer,
/// audience, nonce or state is compared as the bytes it is (§5.2 rule 2).
@inline(__always)
func bytesEqual(_ a: String, _ b: String) -> Bool {
    a.utf8.elementsEqual(b.utf8)
}
