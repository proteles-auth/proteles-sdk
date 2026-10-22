import Foundation
import Security
import Testing
@testable import ProtelesAuth

@Suite("PKCE, state and nonce")
struct PKCETests {
    /// RFC 7636 Appendix B: the octets, the verifier they encode to, and its
    /// S256 challenge.
    @Test func rfc7636AppendixBKnownAnswer() {
        let octets: [UInt8] = [
            116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
            187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
            132, 141, 121,
        ]
        let pkce = PKCE(verifierBytes: Data(octets))
        #expect(pkce.verifier == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        #expect(pkce.challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        #expect(PKCE.challenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        #expect(pkce.method == "S256")
    }

    @Test func aGeneratedPairIsFortyThreeCharactersOfBase64URL() throws {
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        for _ in 0..<64 {
            let pkce = try PKCE.generate()
            #expect(pkce.verifier.count == 43)
            #expect(pkce.challenge.count == 43, "the server requires exactly 43 (trap 5)")
            #expect(pkce.verifier.allSatisfy(alphabet.contains))
            #expect(pkce.challenge.allSatisfy(alphabet.contains))
            #expect(PKCE.challenge(for: pkce.verifier) == pkce.challenge)
        }
    }

    @Test func stateAndNonceAreThirtyTwoRandomBytesEach() throws {
        let tokens = try (0..<256).map { _ in try SecureRandom.token() }
        #expect(tokens.allSatisfy { $0.count == 43 && Base64URL.decode($0)?.count == 32 })
        #expect(Set(tokens).count == tokens.count)
    }
}

@Suite("Base64url")
struct Base64URLTests {
    @Test func roundTrips() {
        for length in 0..<40 {
            let data = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) })
            let text = Base64URL.encode(data)
            #expect(!text.contains("=") && !text.contains("+") && !text.contains("/"))
            #expect(Base64URL.decode(text) == data)
        }
    }

    @Test(arguments: [
        "eyJhbGciOiJSUzI1NiJ9=", // padding (§5.2 rule 6)
        "ab+c",                   // standard alphabet
        "ab/c",
        "ab c",
        "a",                      // a length no encoder produces
        "QR",                     // non-canonical: "QQ" is the only spelling of "A"
    ])
    func refuses(_ text: String) {
        #expect(Base64URL.decode(text) == nil)
    }

    @Test func acceptsTheCanonicalSpelling() {
        #expect(Base64URL.decode("QQ") == Data("A".utf8))
        #expect(Base64URL.decode("") == Data())
    }
}

@Suite("RSA public key DER")
struct DERTests {
    /// The PKCS#1 DER written from a JWK's n and e is byte-for-byte what the
    /// platform exports for the same key.
    @Test func matchesThePlatformsOwnEncoding() throws {
        let signer = TestSigner.shared
        let modulus = try #require(Base64URL.decode(signer.n))
        let exponent = try #require(Base64URL.decode(signer.e))
        #expect(modulus.first.map { $0 & 0x80 != 0 } == true, "a 2048-bit modulus has its top bit set, so DER needs a leading zero")
        #expect(DER.rsaPublicKey(modulus: modulus, exponent: exponent) == signer.publicKeyDER)
    }

    @Test func integersAreMinimalAndNonNegative() {
        #expect(DER.integer(Data([0x01, 0x00, 0x01])) == Data([0x02, 0x03, 0x01, 0x00, 0x01]))
        #expect(DER.integer(Data([0x00, 0x00, 0x7F])) == Data([0x02, 0x01, 0x7F]))
        #expect(DER.integer(Data([0x80])) == Data([0x02, 0x02, 0x00, 0x80]))
        #expect(DER.length(0x7F) == [0x7F])
        #expect(DER.length(0x80) == [0x81, 0x80])
        #expect(DER.length(0x101) == [0x82, 0x01, 0x01])
    }
}

@Suite("Form encoding")
struct FormEncodingTests {
    @Test func encodesEverythingOutsideTheUnreservedSet() {
        #expect(FormEncoding.percentEncode("a+b c&d=e/f:g~h.i_j-k") == "a%2Bb%20c%26d%3De%2Ff%3Ag~h.i_j-k")
        #expect(FormEncoding.percentEncode("é") == "%C3%A9")
    }

    @Test func decodesPlusAsSpaceAndPercentEscapes() throws {
        let fields = try #require(FormEncoding.decodeExactly("a=1+2&b=%2B&c=&d&e=https%3A%2F%2Fx.example&a=%C3%A9"))
        #expect(fields.map(\.name) == ["a", "b", "c", "d", "e", "a"], "a repeated name is kept, for the caller to refuse")
        #expect(fields.map(\.value) == ["1 2", "+", "", "", "https://x.example", "é"])
    }

    @Test("a query with any escape that does not decode is not a query the SDK reads", arguments: [
        "a=1&b=%zz", "a=%", "a=%4", "a=%E9", "%zz=1", "a=1&a=%C3",
    ])
    func malformedEscapes(_ query: String) {
        #expect(FormEncoding.decodeExactly(query) == nil, "\(query)")
    }
}

@Suite("Retry-After")
struct RetryAfterTests {
    @Test func delaySeconds() {
        #expect(RetryAfter.parse("30", now: Fixture.t0) == 30)
        #expect(RetryAfter.parse(" 7 ", now: Fixture.t0) == 7)
    }

    @Test func httpDate() {
        // Fixture.t0 is 2027-01-15T08:00:00Z.
        #expect(RetryAfter.parse("Fri, 15 Jan 2027 08:01:30 GMT", now: Fixture.t0) == 90)
        #expect(RetryAfter.parse("Fri, 15 Jan 2027 07:00:00 GMT", now: Fixture.t0) == 0)
    }

    @Test func garbageIsNoAdvice() {
        #expect(RetryAfter.parse(nil, now: Fixture.t0) == nil)
        #expect(RetryAfter.parse("soon", now: Fixture.t0) == nil)
        #expect(RetryAfter.parse("-5", now: Fixture.t0) == nil)
    }

    @Test("capped at an hour, however it is written — and never infinite")
    func capped() {
        #expect(RetryAfter.parse("3600", now: Fixture.t0) == 3600)
        #expect(RetryAfter.parse("7200", now: Fixture.t0) == 3600)
        #expect(RetryAfter.parse("99999999999999999999", now: Fixture.t0) == 3600)
        #expect(RetryAfter.parse(String(repeating: "9", count: 400), now: Fixture.t0) == 3600)
        #expect(RetryAfter.parse("Sat, 16 Jan 2027 08:00:00 GMT", now: Fixture.t0) == 3600)
    }

    @Test("describing a rate limit never traps, whatever the value")
    func describingNeverTraps() {
        for value in [0, 1.2, 3600, 1e20, .greatestFiniteMagnitude, .infinity, -.infinity, .nan] as [TimeInterval] {
            #expect(!ProtelesAuthError.rateLimited(retryAfter: value).localizedDescription.isEmpty)
        }
        #expect(ProtelesAuthError.rateLimited(retryAfter: 1.2).localizedDescription.contains("retry after 2 s"))
    }
}

@Suite("Strict JSON (§5.2: a member named twice, a header that does not parse)")
struct StrictJSONTests {
    private func parse(_ text: String) throws -> JSONValue {
        try StrictJSON.parse(Data(text.utf8))
    }

    private func failure(_ bytes: Data) -> JSONParseFailure? {
        do {
            _ = try StrictJSON.parse(bytes)
            return nil
        } catch let failure as JSONParseFailure {
            return failure
        } catch {
            return nil
        }
    }

    private func failure(_ text: String) -> JSONParseFailure? { failure(Data(text.utf8)) }

    @Test func readsWhatJSONParseReads() throws {
        #expect(try parse(#" {"a": [1, -2.5e3, true, false, null, "x\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00"]} "#) == .object([
            "a": .array([.number(1), .number(-2500), .bool(true), .bool(false), .null, .string("x\"\\/\u{08}\u{0C}\n\r\té😀")]),
        ]))
        #expect(try parse("0") == .number(0))
        #expect(try parse("-0.0E+1") == .number(-0.0))
        #expect(try parse(#""""#) == .string(""))
        #expect(try parse("{}") == .object([:]))
        #expect(try parse("[]") == .array([]))
    }

    @Test("a member named twice is refused, at any depth", arguments: [
        #"{"sub":"a","sub":"b"}"#,
        #"{"a":{"x":1,"x":1}}"#,
        #"[{"x":1,"x":2}]"#,
        #"{"s\u0075b":"a","sub":"b"}"#,         // one name, spelled twice
        "{\"\u{00E9}\":1,\"\u{00E9}\":2}",         // the same code points twice
    ])
    func duplicates(_ text: String) {
        #expect(failure(text) == .duplicateMember, "\(text)")
    }

    @Test("names are compared by code point, as the reference and the Android SDK compare them: canonically equivalent spellings are two members — and neither is kept")
    func canonicallyEquivalentNames() throws {
        // U+00E9, and e + U+0301: equal as Swift Strings, distinct as JSON names.
        let object = try #require(parse("{\"\u{00E9}\":1,\"e\u{0301}\":2,\"sub\":\"u\"}").objectValue)
        #expect(object["\u{00E9}"] == nil && object["e\u{0301}"] == nil, "ambiguous here, so not readable by either spelling")
        #expect(object["sub"] == .string("u"))
        #expect(object.count == 1)
        #expect(failure("{\"\u{00E9}\":1,\"e\u{0301}\":2,\"e\u{0301}\":3}") == .duplicateMember, "a spelling repeated is still a duplicate")
    }

    @Test("a syntax error is the reason that wins over a duplicate, as in the reference")
    func syntaxBeatsDuplicate() {
        #expect(failure(#"{"a":1,"a":2"#) == .notJSON)
    }

    @Test("not JSON", arguments: [
        "", " ", "not json", "{", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "[1,]", "[1 2]", "01", "1.", ".5", "+1",
        "1e", "-", "tru", "nul", "'a'", "{a:1}", "\"\u{01}\"", "\"\\x\"", "\"\\u12\"", "\"\\ud800\"", "\"\\udc00\"",
        "\"\\ud800\\u0041\"", "{}{}", "{} x", "/* c */ {}", "[NaN]", "[Infinity]", "\"unterminated",
    ])
    func notJSON(_ text: String) {
        #expect(failure(text) == .notJSON, "\(text.debugDescription)")
    }

    @Test("bytes that are not well-formed UTF-8, or begin with a byte-order mark, are not JSON")
    func notUTF8() {
        #expect(failure(Data([0x22, 0xFF, 0x22])) == .notJSON)
        #expect(failure(Data([0x22, 0xC0, 0xAF, 0x22])) == .notJSON, "an overlong /")
        #expect(failure(Data([0x22, 0xED, 0xA0, 0x80, 0x22])) == .notJSON, "an encoded surrogate")
        #expect(failure(Data([0xEF, 0xBB, 0xBF, 0x7B, 0x7D])) == .notJSON, "a BOM")
    }

    @Test func nestingIsBounded() throws {
        let deep = String(repeating: "[", count: StrictJSON.maximumDepth) + String(repeating: "]", count: StrictJSON.maximumDepth)
        _ = try parse(deep)
        let deeper = "[" + deep + "]"
        #expect(failure(deeper) == .notJSON)
    }

    @Test("an object is asked for by name: another type is not JSON the verifier can use")
    func strictObject() throws {
        #expect(try JSONValue.parseStrictObject(Data(#"{"a":1}"#.utf8)) == ["a": .number(1)])
        #expect(throws: JSONParseFailure.notJSON) { try JSONValue.parseStrictObject(Data("[]".utf8)) }
        #expect(throws: JSONParseFailure.duplicateMember) { try JSONValue.parseStrictObject(Data(#"[{"a":1,"a":1}]"#.utf8)) }
    }
}

@Suite("The ID token's header and payload, parsed strictly")
struct StrictTokenTests {
    private func verify(header: String, payload: [String: JSONValue]? = nil, rawPayload: String? = nil) async -> IDTokenRejection? {
        let signer = TestSigner.shared
        let claims = payload ?? [
            "iss": .string(Fixture.issuer), "sub": .string("u"), "aud": .string(Fixture.clientId),
            "exp": .number(Fixture.t0.timeIntervalSince1970 + 900),
        ]
        let h = Base64URL.encode(Data(header.utf8))
        let p = Base64URL.encode(rawPayload.map { Data($0.utf8) } ?? TestSigner.encode(.object(claims)))
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(signer.privateKey, .rsaSignatureMessagePKCS1v15SHA256, Data("\(h).\(p)".utf8) as CFData, &error)! as Data
        let token = "\(h).\(p).\(Base64URL.encode(signature))"
        let expectations = IDTokenExpectations(
            issuer: Fixture.issuer, audience: Fixture.clientId, nonce: .skippedForRefreshGrant, accessToken: nil, now: Fixture.t0
        )
        do {
            _ = try await IDTokenVerifier.verify(token, expecting: expectations, keys: JSONWebKeySet(json: .object(["keys": .array([signer.jwk])])))
            return nil
        } catch ProtelesAuthError.idTokenRejected(let reason) {
            return reason
        } catch {
            return nil
        }
    }

    private let good = #"{"alg":"RS256","kid":"test-key-1"}"#

    @Test func theControlVerifies() async {
        #expect(await verify(header: good) == nil)
    }

    @Test("a header naming a member twice — even two identical algs — is refused before the algorithm is read")
    func duplicateInTheHeader() async {
        #expect(await verify(header: #"{"alg":"RS256","alg":"RS256","kid":"test-key-1"}"#) == .duplicateMember)
        #expect(await verify(header: #"{"alg":"none","kid":"test-key-1","kid":"x"}"#) == .duplicateMember)
    }

    @Test("a header that is JSON but not an object is not a header", arguments: ["[]", "\"RS256\"", "null", "1"])
    func headerNotAnObject(_ header: String) async {
        #expect(await verify(header: header) == .headerNotJSON)
    }

    @Test("crit is refused whatever its value, after the algorithm")
    func crit() async {
        #expect(await verify(header: #"{"alg":"RS256","kid":"test-key-1","crit":null}"#) == .criticalHeader)
        #expect(await verify(header: #"{"alg":"RS256","kid":"test-key-1","crit":[]}"#) == .criticalHeader)
        #expect(await verify(header: #"{"alg":"HS256","kid":"test-key-1","crit":["b64"]}"#) == .algorithm)
    }

    @Test("a signed payload that does not parse, or names a claim twice, is refused for that")
    func payload() async {
        #expect(await verify(header: good, rawPayload: "not json") == .payloadNotJSON)
        #expect(await verify(header: good, rawPayload: "[]") == .payloadNotJSON)
        #expect(await verify(header: good, rawPayload: #"{"iss":"https://auth.example.test","sub":"u","aud":"com.example.mobile","exp":1800000900,"sub":"v"}"#) == .duplicateMember)
    }
}
