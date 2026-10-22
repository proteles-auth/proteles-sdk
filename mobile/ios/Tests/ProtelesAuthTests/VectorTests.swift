import Foundation
import Testing
@testable import ProtelesAuth

/// The shared ID-token vectors (docs/mobile-SDKs.md §5.2), read from
/// mobile/vectors at test time — not a copy — so a refreshed vectors.json is
/// what this verifier is held to, as it is for the Android and JavaScript SDKs.
struct Vector: Sendable, CustomTestStringConvertible {
    let name: String
    let token: String
    let jwks: JSONValue
    let verdict: String
    let why: String
    let issuer: String
    let audience: String
    let nonce: String?
    let accessToken: String?
    let now: Double

    var testDescription: String { "\(name) → \(verdict)" }

    /// `mobile/vectors/vectors.json`, found relative to this source file:
    /// mobile/ios/Tests/ProtelesAuthTests/VectorTests.swift → mobile. The
    /// package's manifest is at the repository root, so a checkout that builds
    /// it always has mobile/vectors beside mobile/ios.
    static let fileURL: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // ProtelesAuthTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // ios
        .deletingLastPathComponent() // mobile
        .appendingPathComponent("vectors/vectors.json")

    static func load() throws -> [Vector] {
        let data = try Data(contentsOf: fileURL)
        guard let root = JSONValue.parseObject(data), let vectors = root["vectors"]?.arrayValue else {
            throw VectorFileError("vectors.json has no vectors array")
        }
        return try vectors.map { value in
            guard let v = value.objectValue,
                  let name = v["name"]?.stringValue,
                  let token = v["token"]?.stringValue,
                  let jwks = v["jwks"],
                  let verdict = v["verdict"]?.stringValue,
                  let expect = v["expect"]?.objectValue,
                  let issuer = expect["issuer"]?.stringValue,
                  let audience = expect["audience"]?.stringValue,
                  let now = expect["now"]?.numberValue else {
                throw VectorFileError("a vector is missing a field: \(value)")
            }
            // `null` and a string are different expectations; anything else is
            // a malformed file, not a skip.
            func nullable(_ key: String) throws -> String? {
                switch expect[key] {
                case .null?: return nil
                case .string(let s)?: return s
                default: throw VectorFileError("\(name): expect.\(key) is neither null nor a string")
                }
            }
            return Vector(
                name: name, token: token, jwks: jwks, verdict: verdict, why: v["why"]?.stringValue ?? "",
                issuer: issuer, audience: audience, nonce: try nullable("nonce"),
                accessToken: try nullable("accessToken"), now: now
            )
        }
    }
}

struct VectorFileError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Why each refusing vector must be refused: `EXPECTED_REASON` in
/// `mobile/vectors/reference-verify.mjs`, read from that file at test time
/// rather than retyped here, so the reference and this SDK cannot drift apart
/// (the Android SDK reads it the same way). A refusal for any other reason
/// means the vector did not test what its name says, so the reason is
/// asserted, not only the verdict.
enum ReferenceReasons {
    /// Beside `vectors.json`, so the table and the vectors always come from
    /// the same place.
    static let fileURL = Vector.fileURL.deletingLastPathComponent().appendingPathComponent("reference-verify.mjs")

    /// Vector name → reason name, as the reference spells both.
    static func load() throws -> [String: String] {
        let source = try String(contentsOf: fileURL, encoding: .utf8)
        guard let start = source.range(of: "const EXPECTED_REASON = {"),
              let end = source.range(of: "};", range: start.upperBound..<source.endIndex) else {
            throw VectorFileError("EXPECTED_REASON not found in reference-verify.mjs")
        }
        var reasons: [String: String] = [:]
        for line in source[start.upperBound..<end.lowerBound].split(separator: "\n") {
            // `  "vector-name": "reason",`
            let quoted = line.split(separator: "\"", omittingEmptySubsequences: false)
            guard quoted.count >= 5 else { continue }
            let name = String(quoted[1]), reason = String(quoted[3])
            guard reasons.updateValue(reason, forKey: name) == nil else {
                throw VectorFileError("\(name) is listed twice in EXPECTED_REASON")
            }
        }
        return reasons
    }
}

@Suite("The shared ID-token vectors")
struct VectorTests {
    @Test("every vector reaches its verdict, each refusal for its own reason", arguments: try Vector.load())
    func vector(_ vector: Vector) async throws {
        let keys = JSONWebKeySet(json: vector.jwks)
        let expectations = IDTokenExpectations(
            issuer: vector.issuer,
            audience: vector.audience,
            nonce: vector.nonce.map(IDTokenExpectations.Nonce.required) ?? .skippedForRefreshGrant,
            accessToken: vector.accessToken,
            now: Date(timeIntervalSince1970: vector.now)
        )
        do {
            let verified = try await IDTokenVerifier.verify(vector.token, expecting: expectations, keys: keys)
            #expect(vector.verdict == "accept", "\(vector.name) was accepted; it must be refused: \(vector.why)")
            #expect(!verified.subject.isEmpty)
        } catch ProtelesAuthError.idTokenRejected(let reason) {
            #expect(vector.verdict == "reject", "\(vector.name) was refused (\(reason.rawValue)); it must be accepted: \(vector.why)")
            if vector.verdict == "reject" {
                let expected = try ReferenceReasons.load()[vector.name]
                #expect(reason.rawValue == expected, "\(vector.name) was refused for \(reason.rawValue), not for \(expected ?? "a reason the reference does not list")")
            }
        }
    }

    /// Not a count: the file grows as rules are settled (29 vectors, then 35),
    /// and a pinned number fails for the file being right. What must hold is
    /// that the file and the reference's table describe the same refusals,
    /// name for name, and that the run read a real file.
    @Test("the vector file is complete: unique names, and the reference's reason for every refusal and no other")
    func completeness() throws {
        let vectors = try Vector.load()
        let reasons = try ReferenceReasons.load()
        #expect(Set(vectors.map(\.name)).count == vectors.count, "vector names are unique")
        #expect(vectors.allSatisfy { $0.verdict == "accept" || $0.verdict == "reject" })
        let refusals = Set(vectors.filter { $0.verdict == "reject" }.map(\.name))
        // A run that read an empty or truncated file, or parsed nothing out of
        // the reference, proves nothing: both sides must be there.
        #expect(!refusals.isEmpty && vectors.contains { $0.verdict == "accept" })
        #expect(!reasons.isEmpty)
        #expect(refusals.subtracting(reasons.keys).isEmpty, "refusing vectors with no reason in the reference: \(refusals.subtracting(reasons.keys).sorted())")
        #expect(Set(reasons.keys).subtracting(refusals).isEmpty, "reasons in the reference for no refusing vector: \(Set(reasons.keys).subtracting(refusals).sorted())")
        // The clock the vectors were generated for is this verifier's.
        let constants = try #require(JSONValue.parseObject(Data(contentsOf: Vector.fileURL))?["constants"]?.objectValue)
        #expect(constants["clockSkewSeconds"]?.numberValue == IDTokenVerifier.clockSkew)
    }

    /// Every reason the reference gives is one of this SDK's rejections, by
    /// its raw value — so a failure message reads the same in both.
    @Test func everyReferenceReasonIsARejection() throws {
        let ours = Set(IDTokenRejection.allCases.map(\.rawValue))
        for (name, reason) in try ReferenceReasons.load() {
            #expect(ours.contains(reason), "\(name): the reference's reason \(reason) is no IDTokenRejection")
        }
    }
}
