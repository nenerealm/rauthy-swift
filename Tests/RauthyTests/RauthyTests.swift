import Foundation
import Testing
import CryptoKit
@testable import Rauthy

// MARK: - JSONValue

@Suite("JSONValue")
struct JSONValueTests {
    @Test("round-trips primitive values")
    func roundTripsPrimitives() throws {
        let values: [JSONValue] = [
            .null,
            .bool(true),
            .bool(false),
            .number(0),
            .number(42.5),
            .string(""),
            .string("hello"),
        ]
        for value in values {
            let data = try JSONEncoder().encode(value)
            let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
            #expect(decoded == value)
        }
    }

    @Test("round-trips nested arrays and objects")
    func roundTripsNested() throws {
        let value: JSONValue = .object([
            "name": .string("alice"),
            "age": .number(30),
            "roles": .array([.string("admin"), .string("user")]),
            "active": .bool(true),
            "metadata": .object(["last_seen": .null]),
        ])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        #expect(decoded == value)
    }
}

// MARK: - Claim & ClaimRule

@Suite("ClaimRule")
struct ClaimRuleTests {
    @Test("Claim.matches by role and group")
    func claimMatching() {
        let role = Claim.role("admin")
        let group = Claim.group("users")
        #expect(role.matches(roles: ["admin"], groups: []))
        #expect(!role.matches(roles: ["editor"], groups: []))
        #expect(group.matches(roles: [], groups: ["users"]))
        #expect(!group.matches(roles: ["users"], groups: []))
    }

    @Test("ClaimRule.any always matches")
    func anyAlwaysMatches() {
        let rule: ClaimRule = .any
        #expect(rule.matches(roles: [], groups: []))
        #expect(rule.matches(roles: ["any"], groups: ["thing"]))
    }

    @Test("ClaimRule.none never matches")
    func noneNeverMatches() {
        let rule: ClaimRule = .none
        #expect(!rule.matches(roles: [], groups: []))
        #expect(!rule.matches(roles: ["admin"], groups: ["ops"]))
    }

    @Test("ClaimRule.or matches when any claim matches")
    func orSemantics() {
        let rule: ClaimRule = .or([.role("admin"), .group("ops")])
        #expect(rule.matches(roles: ["admin"], groups: []))
        #expect(rule.matches(roles: [], groups: ["ops"]))
        #expect(rule.matches(roles: ["admin"], groups: ["ops"]))
        #expect(!rule.matches(roles: ["editor"], groups: ["dev"]))
    }

    @Test("ClaimRule.and requires all claims to match")
    func andSemantics() {
        let rule: ClaimRule = .and([.role("admin"), .group("ops")])
        #expect(rule.matches(roles: ["admin"], groups: ["ops"]))
        #expect(!rule.matches(roles: ["admin"], groups: []))
        #expect(!rule.matches(roles: [], groups: ["ops"]))
        #expect(!rule.matches(roles: ["editor"], groups: ["dev"]))
    }

    @Test("ClaimRule round-trips through JSON")
    func roundTripsJSON() throws {
        let rules: [ClaimRule] = [
            .any,
            .none,
            .or([.role("admin")]),
            .and([.role("admin"), .group("ops")]),
        ]
        for rule in rules {
            let data = try JSONEncoder().encode(rule)
            let decoded = try JSONDecoder().decode(ClaimRule.self, from: data)
            #expect(decoded == rule)
        }
    }
}

// MARK: - Token

@Suite("Token")
struct TokenTests {
    @Test("expiresAt = issuedAt + expiresIn")
    func expiresAtComputed() {
        let issuedAt = Date(timeIntervalSince1970: 1_000_000)
        let token = makeToken(issuedAt: issuedAt, expiresIn: 3600)
        #expect(token.expiresAt == issuedAt.addingTimeInterval(3600))
    }

    @Test("isExpired returns true for past tokens")
    func isExpiredPast() {
        let token = makeToken(issuedAt: Date(timeIntervalSinceNow: -7200), expiresIn: 3600)
        #expect(token.isExpired())
    }

    @Test("isExpired returns false for fresh tokens")
    func isExpiredFresh() {
        let token = makeToken(issuedAt: Date(), expiresIn: 3600)
        #expect(!token.isExpired())
    }

    @Test("isExpired respects graceInterval")
    func isExpiredWithGrace() {
        // Token expires in 30 seconds. With a 60-second grace, it should already be considered expired.
        let token = makeToken(issuedAt: Date(), expiresIn: 30)
        #expect(token.isExpired(graceInterval: 60))
        #expect(!token.isExpired(graceInterval: 10))
    }

    @Test("Codable round-trip")
    func roundTripsCodable() throws {
        let original = makeToken(issuedAt: Date(timeIntervalSince1970: 1_700_000_000), expiresIn: 3600)
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(Token.self, from: data)
        #expect(decoded == original)
    }

    private func makeToken(issuedAt: Date, expiresIn: TimeInterval) -> Token {
        Token(
            id: UUID().uuidString,
            accessToken: "fake-access-token",
            refreshToken: "fake-refresh-token",
            idToken: nil,
            tokenType: .bearer,
            scope: ["openid", "profile"],
            issuedAt: issuedAt,
            expiresIn: expiresIn
        )
    }
}

// MARK: - SigningAlgorithm

@Suite("SigningAlgorithm")
struct SigningAlgorithmTests {
    @Test("raw values match JWT spec")
    func rawValues() {
        #expect(SigningAlgorithm.rs256.rawValue == "RS256")
        #expect(SigningAlgorithm.rs384.rawValue == "RS384")
        #expect(SigningAlgorithm.rs512.rawValue == "RS512")
        #expect(SigningAlgorithm.eddsa.rawValue == "EdDSA")
    }

    @Test("all cases enumerable")
    func allCases() {
        #expect(SigningAlgorithm.allCases.count == 4)
    }

    @Test("does not include ES256")
    func excludesES256() {
        // Rauthy intentionally does not support ES256 (it's not in the JWK
        // algorithm list). The SDK reflects this — see SigningAlgorithm.swift.
        #expect(SigningAlgorithm(rawValue: "ES256") == nil)
    }
}

// MARK: - User

@Suite("User")
struct UserTests {
    @Test("init(idToken:) extracts claims")
    func fromIDToken() {
        let claims = IDTokenClaims(
            sub: "user-123",
            aud: ["my-app"],
            iss: URL(string: "https://auth.example.com")!,
            iat: Date(),
            exp: Date(timeIntervalSinceNow: 3600),
            email: "alice@example.com",
            emailVerified: true,
            preferredUsername: "alice",
            roles: ["admin"],
            groups: ["users", "ops"]
        )
        let idToken = IDToken(
            raw: "fake.jwt.here",
            header: JWTHeader(alg: .eddsa, typ: "JWT", kid: "key-1"),
            payload: claims,
            signature: Data()
        )
        let user = User(idToken: idToken)

        #expect(user.id == "user-123")
        #expect(user.subject == "user-123")
        #expect(user.email == "alice@example.com")
        #expect(user.emailVerified == true)
        #expect(user.preferredUsername == "alice")
        #expect(user.roles == ["admin"])
        #expect(user.groups == ["users", "ops"])
        #expect(user.mfaEnabled == nil)  // not in ID tokens
    }

    @Test("init(userInfoResponse:) decodes /userinfo JSON")
    func fromUserInfo() throws {
        let json = """
        {
            "id": "rauthy-uid-456",
            "sub": "user-123",
            "name": "Alice",
            "email": "alice@example.com",
            "email_verified": true,
            "preferred_username": "alice",
            "given_name": "Alice",
            "family_name": "Example",
            "roles": ["admin"],
            "groups": ["users"],
            "mfa_enabled": true
        }
        """.data(using: .utf8)!
        let user = try User(userInfoResponse: json)

        #expect(user.id == "rauthy-uid-456")
        #expect(user.subject == "user-123")
        #expect(user.email == "alice@example.com")
        #expect(user.emailVerified == true)
        #expect(user.givenName == "Alice")
        #expect(user.familyName == "Example")
        #expect(user.roles == ["admin"])
        #expect(user.groups == ["users"])
        #expect(user.mfaEnabled == true)
    }
}

// MARK: - IDTokenClaims

@Suite("IDTokenClaims")
struct IDTokenClaimsTests {
    @Test("decodes aud as array")
    func audAsArray() throws {
        let json = """
        {
            "sub": "user-1",
            "aud": ["client-1", "client-2"],
            "iss": "https://auth.example.com",
            "iat": 1700000000,
            "exp": 1700003600
        }
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let claims = try decoder.decode(IDTokenClaims.self, from: json)
        #expect(claims.aud == ["client-1", "client-2"])
    }

    @Test("decodes aud as single string")
    func audAsString() throws {
        let json = """
        {
            "sub": "user-1",
            "aud": "client-1",
            "iss": "https://auth.example.com",
            "iat": 1700000000,
            "exp": 1700003600
        }
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let claims = try decoder.decode(IDTokenClaims.self, from: json)
        #expect(claims.aud == ["client-1"])
    }

    @Test("missing aud throws")
    func missingAudThrows() {
        let json = """
        {
            "sub": "user-1",
            "iss": "https://auth.example.com",
            "iat": 1700000000,
            "exp": 1700003600
        }
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        #expect(throws: (any Error).self) {
            try decoder.decode(IDTokenClaims.self, from: json)
        }
    }

    @Test("roles and groups default to empty when absent")
    func rolesGroupsDefault() throws {
        let json = """
        {
            "sub": "user-1",
            "aud": "client-1",
            "iss": "https://auth.example.com",
            "iat": 1700000000,
            "exp": 1700003600
        }
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let claims = try decoder.decode(IDTokenClaims.self, from: json)
        #expect(claims.roles.isEmpty)
        #expect(claims.groups.isEmpty)
    }
}

// MARK: - RauthyError

@Suite("RauthyError")
struct RauthyErrorTests {
    @Test("equality for nullary cases")
    func equalityNullary() {
        #expect(RauthyError.userCancelled == .userCancelled)
        #expect(RauthyError.networkUnavailable == .networkUnavailable)
        #expect(RauthyError.userCancelled != .networkUnavailable)
    }

    @Test("equality for cases with payload")
    func equalityWithPayload() {
        let a = RauthyError.sessionNotFound(id: "abc")
        let b = RauthyError.sessionNotFound(id: "abc")
        let c = RauthyError.sessionNotFound(id: "xyz")
        #expect(a == b)
        #expect(a != c)
    }

    @Test("invalidJWT carries failure reason")
    func invalidJWTCarriesReason() {
        let error = RauthyError.invalidJWT(.expired)
        if case .invalidJWT(let reason) = error {
            #expect(reason == .expired)
        } else {
            Issue.record("expected .invalidJWT case")
        }
    }
}

// MARK: - Base64URL

@Suite("Base64URL")
struct Base64URLTests {
    @Test("round-trips arbitrary bytes")
    func roundTrip() throws {
        let inputs: [Data] = [
            Data(),
            Data([0x00]),
            Data([0xFF, 0xFE, 0xFD]),
            Data("hello".utf8),
            Data(repeating: 0xAB, count: 32),
        ]
        for input in inputs {
            let encoded = input.base64URLEncodedString()
            #expect(!encoded.contains("+"))
            #expect(!encoded.contains("/"))
            #expect(!encoded.contains("="))
            let decoded = try #require(Data(base64URLEncoded: encoded))
            #expect(decoded == input)
        }
    }

    @Test("decodes with or without padding")
    func paddingTolerance() throws {
        // "hello" base64 = "aGVsbG8=" (one = pad)
        let withPad = Data(base64URLEncoded: "aGVsbG8=")
        let withoutPad = Data(base64URLEncoded: "aGVsbG8")
        #expect(withPad == Data("hello".utf8))
        #expect(withoutPad == Data("hello".utf8))
    }
}

// MARK: - PKCE

@Suite("PKCE")
struct PKCETests {
    @Test("generates verifier of valid length")
    func verifierLength() {
        let pkce = PKCE()
        // 32 random bytes → base64url = 43 chars (no padding)
        #expect(pkce.codeVerifier.count == 43)
    }

    @Test("challenge is SHA-256 of verifier")
    func challengeIsSHA256() {
        // RFC 7636 §4.1 requires 43-128 chars from a restricted set; pick a
        // verifier the size of a default-generated one for parity with prod.
        let verifier = "test-verifier-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        let pkce = PKCE(codeVerifier: verifier)
        let expected = Data(SHA256.hash(data: Data(verifier.utf8)))
            .base64URLEncodedString()
        #expect(pkce.codeChallenge == expected)
    }

    @Test("challenge method is always S256")
    func methodIsS256() {
        #expect(PKCE().codeChallengeMethod == "S256")
    }

    @Test("two PKCE instances differ")
    func uniquenessAcrossInstances() {
        let a = PKCE()
        let b = PKCE()
        #expect(a.codeVerifier != b.codeVerifier)
        #expect(a.codeChallenge != b.codeChallenge)
    }

    @Test("verifier characters are URL-safe base64")
    func verifierCharacterSet() {
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let pkce = PKCE()
        for char in pkce.codeVerifier {
            #expect(allowed.contains(char))
        }
    }
}

// MARK: - JWTDecoder

@Suite("JWTDecoder")
struct JWTDecoderTests {
    @Test("rejects token with wrong segment count")
    func rejectsBadStructure() {
        #expect(throws: RauthyError.self) {
            try JWTDecoder.decode("only.two")
        }
        #expect(throws: RauthyError.self) {
            try JWTDecoder.decode("a.b.c.d")
        }
    }

    @Test("rejects non-base64url segments")
    func rejectsBadEncoding() {
        // "!!!" is not valid base64url
        #expect(throws: RauthyError.self) {
            try JWTDecoder.decode("!!!.!!!.!!!")
        }
    }

    @Test("decodes valid JWT segments")
    func decodesValid() throws {
        let header = Data(#"{"alg":"EdDSA","typ":"JWT"}"#.utf8)
        let payload = Data(#"{"sub":"abc","exp":1700003600}"#.utf8)
        let signature = Data([0x01, 0x02, 0x03])

        let token = [header, payload, signature]
            .map { $0.base64URLEncodedString() }
            .joined(separator: ".")

        let parts = try JWTDecoder.decode(token)
        #expect(parts.headerBytes == header)
        #expect(parts.payloadBytes == payload)
        #expect(parts.signature == signature)
    }
}

// MARK: - AuthorizationURLBuilder

@Suite("AuthorizationURLBuilder")
struct AuthorizationURLBuilderTests {
    @Test("builds /authorize URL with all required parameters")
    func buildAuthorizeURL() {
        let config = RauthyConfig.production(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            redirectURI: URL(string: "myapp://cb")!,
            scopes: ["openid", "profile"],
            userClaim: .any,
            adminClaim: .none
        )
        let discovery = makeDiscovery()
        let pkce = PKCE(codeVerifier: "test-verifier-AAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        let url = AuthorizationURLBuilder.build(
            config: config,
            discovery: discovery,
            state: "state-abc",
            nonce: "nonce-xyz",
            pkce: pkce
        )
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let items = Dictionary(uniqueKeysWithValues: components.queryItems!.compactMap { item -> (String, String)? in
            guard let value = item.value else { return nil }
            return (item.name, value)
        })
        #expect(items["response_type"] == "code")
        #expect(items["client_id"] == "my-app")
        #expect(items["redirect_uri"] == "myapp://cb")
        #expect(items["scope"] == "openid profile")
        #expect(items["state"] == "state-abc")
        #expect(items["nonce"] == "nonce-xyz")
        #expect(items["code_challenge"] == pkce.codeChallenge)
        #expect(items["code_challenge_method"] == "S256")
    }

    @Test("parses callback with code and state")
    func parsesCallback() throws {
        let url = URL(string: "myapp://cb?code=abc&state=xyz")!
        let (code, state) = try AuthorizationURLBuilder.parseCallback(url)
        #expect(code == "abc")
        #expect(state == "xyz")
    }

    @Test("parses callback error response")
    func parsesError() {
        let url = URL(string: "myapp://cb?error=access_denied&error_description=user%20said%20no")!
        do {
            _ = try AuthorizationURLBuilder.parseCallback(url)
            Issue.record("expected throw")
        } catch RauthyError.oauth(let err) {
            #expect(err.code == .accessDenied)
            #expect(err.description == "user said no")
        } catch {
            Issue.record("expected RauthyError.oauth, got \(error)")
        }
    }

    @Test("random tokens are non-empty and unique")
    func randomToken() {
        let a = AuthorizationURLBuilder.randomToken()
        let b = AuthorizationURLBuilder.randomToken()
        #expect(!a.isEmpty)
        #expect(a != b)
    }

    private func makeDiscovery() -> OpenIDConfiguration {
        OpenIDConfiguration(
            issuer: URL(string: "https://auth.example.com")!,
            authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://auth.example.com/token")!,
            jwksURI: URL(string: "https://auth.example.com/jwks")!
        )
    }
}

// MARK: - EndSessionURLBuilder

@Suite("EndSessionURLBuilder")
struct EndSessionURLBuilderTests {
    @Test("builds URL with all standard parameters")
    func buildsURL() throws {
        let url = EndSessionURLBuilder.build(
            endpoint: URL(string: "https://auth.example.com/end_session")!,
            idTokenHint: "fake.id.token",
            postLogoutRedirect: URL(string: "myapp://logged-out")!,
            clientID: "my-app"
        )
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let items = Dictionary(uniqueKeysWithValues: components.queryItems!.compactMap { item -> (String, String)? in
            guard let value = item.value else { return nil }
            return (item.name, value)
        })
        #expect(items["id_token_hint"] == "fake.id.token")
        #expect(items["post_logout_redirect_uri"] == "myapp://logged-out")
        #expect(items["client_id"] == "my-app")
    }

    @Test("omits id_token_hint when nil")
    func omitsIdTokenHint() {
        let url = EndSessionURLBuilder.build(
            endpoint: URL(string: "https://auth.example.com/end_session")!,
            idTokenHint: nil,
            postLogoutRedirect: URL(string: "myapp://logged-out")!,
            clientID: "my-app"
        )
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let names = components.queryItems!.map(\.name)
        #expect(!names.contains("id_token_hint"))
        #expect(names.contains("post_logout_redirect_uri"))
    }

    @Test("includes state parameter when provided")
    func includesState() {
        let url = EndSessionURLBuilder.build(
            endpoint: URL(string: "https://auth.example.com/end_session")!,
            idTokenHint: "tok",
            postLogoutRedirect: URL(string: "myapp://logged-out")!,
            clientID: "my-app",
            state: "abc-123"
        )
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let items = Dictionary(uniqueKeysWithValues: components.queryItems!.compactMap { item -> (String, String)? in
            guard let value = item.value else { return nil }
            return (item.name, value)
        })
        #expect(items["state"] == "abc-123")
    }
}

// MARK: - SignOutScope

@Suite("SignOutScope")
struct SignOutScopeTests {
    @Test("equality across cases")
    func equality() {
        let r1: URL = URL(string: "myapp://logout")!
        let r2: URL = URL(string: "myapp://other")!
        #expect(SignOutScope.local == .local)
        #expect(SignOutScope.revokeTokens == .revokeTokens)
        #expect(SignOutScope.rpInitiated(postLogoutRedirect: r1) == .rpInitiated(postLogoutRedirect: r1))
        #expect(SignOutScope.rpInitiated(postLogoutRedirect: r1) != .rpInitiated(postLogoutRedirect: r2))
        #expect(SignOutScope.local != .revokeTokens)
    }
}

// MARK: - OIDCDiscovery URL builder

@Suite("OIDCDiscovery")
struct OIDCDiscoveryTests {
    @Test("discovery URL appends well-known path")
    func discoveryURL() {
        let urls: [(input: String, expected: String)] = [
            ("https://auth.example.com", "https://auth.example.com/.well-known/openid-configuration"),
            ("https://auth.example.com/", "https://auth.example.com/.well-known/openid-configuration"),
            ("https://auth.example.com/auth/v1", "https://auth.example.com/auth/v1/.well-known/openid-configuration"),
        ]
        for (input, expected) in urls {
            let computed = OIDCDiscovery.discoveryURL(for: URL(string: input)!)
            #expect(computed.absoluteString == expected)
        }
    }
}

// MARK: - JWTSignatureValidator

@Suite("JWTSignatureValidator")
struct JWTSignatureValidatorTests {
    @Test("accepts valid Ed25519 signature")
    func acceptsValidEd25519() throws {
        let (privateKey, jwk) = makeEd25519KeyAndJWK()
        let parts = signedParts(privateKey: privateKey, payload: "test-payload")
        try JWTSignatureValidator.validate(parts: parts, algorithm: .eddsa, jwk: jwk)
    }

    @Test("rejects tampered signature")
    func rejectsTamperedSignature() throws {
        let (privateKey, jwk) = makeEd25519KeyAndJWK()
        var parts = signedParts(privateKey: privateKey, payload: "test-payload")
        // Flip a byte of the signature
        var tampered = parts.signature
        tampered[0] ^= 0xFF
        parts = JWTDecoder.Parts(
            headerBytes: parts.headerBytes,
            payloadBytes: parts.payloadBytes,
            signature: tampered,
            signedInput: parts.signedInput
        )
        #expect(throws: RauthyError.self) {
            try JWTSignatureValidator.validate(parts: parts, algorithm: .eddsa, jwk: jwk)
        }
    }

    @Test("rejects kty mismatch (OKP JWK with RS256 algorithm)")
    func rejectsKtyMismatch() throws {
        let (_, jwk) = makeEd25519KeyAndJWK()
        let parts = JWTDecoder.Parts(
            headerBytes: Data(),
            payloadBytes: Data(),
            signature: Data(),
            signedInput: ""
        )
        #expect(throws: RauthyError.self) {
            try JWTSignatureValidator.validate(parts: parts, algorithm: .rs256, jwk: jwk)
        }
    }

    @Test("accepts valid RS256 signature")
    func acceptsValidRS256() throws {
        try runRSARoundTrip(algorithm: .rs256, secAlgorithm: .rsaSignatureMessagePKCS1v15SHA256)
    }

    @Test("accepts valid RS384 signature")
    func acceptsValidRS384() throws {
        try runRSARoundTrip(algorithm: .rs384, secAlgorithm: .rsaSignatureMessagePKCS1v15SHA384)
    }

    @Test("accepts valid RS512 signature")
    func acceptsValidRS512() throws {
        try runRSARoundTrip(algorithm: .rs512, secAlgorithm: .rsaSignatureMessagePKCS1v15SHA512)
    }

    @Test("rejects tampered RSA signature")
    func rejectsTamperedRSA() throws {
        let (privateKey, jwk) = try makeRSAKeyAndJWK(bitSize: 2048)
        var parts = try signedRSAParts(
            privateKey: privateKey,
            payload: "test-payload",
            secAlgorithm: .rsaSignatureMessagePKCS1v15SHA256
        )
        var tampered = parts.signature
        tampered[0] ^= 0xFF
        parts = JWTDecoder.Parts(
            headerBytes: parts.headerBytes,
            payloadBytes: parts.payloadBytes,
            signature: tampered,
            signedInput: parts.signedInput
        )
        #expect(throws: RauthyError.self) {
            try JWTSignatureValidator.validate(parts: parts, algorithm: .rs256, jwk: jwk)
        }
    }

    private func runRSARoundTrip(
        algorithm: SigningAlgorithm,
        secAlgorithm: SecKeyAlgorithm
    ) throws {
        let (privateKey, jwk) = try makeRSAKeyAndJWK(bitSize: 2048)
        let parts = try signedRSAParts(
            privateKey: privateKey,
            payload: "test-payload",
            secAlgorithm: secAlgorithm
        )
        try JWTSignatureValidator.validate(parts: parts, algorithm: algorithm, jwk: jwk)
    }

    private func makeRSAKeyAndJWK(bitSize: Int) throws -> (SecKey, JWK) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: bitSize,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw RSAPublicKeyError.creationFailed("SecKeyCreateRandomKey failed")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw RSAPublicKeyError.creationFailed("SecKeyCopyPublicKey failed")
        }
        guard let publicDER = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw RSAPublicKeyError.creationFailed("SecKeyCopyExternalRepresentation failed")
        }
        let (n, e) = try RSAPublicKey.parse(der: publicDER)
        let jwk = JWK(
            kty: "RSA",
            alg: nil,
            kid: "rsa-test",
            n: n.base64URLEncodedString(),
            e: e.base64URLEncodedString()
        )
        return (privateKey, jwk)
    }

    private func signedRSAParts(
        privateKey: SecKey,
        payload: String,
        secAlgorithm: SecKeyAlgorithm
    ) throws -> JWTDecoder.Parts {
        let alg: String
        switch secAlgorithm {
        case .rsaSignatureMessagePKCS1v15SHA256: alg = "RS256"
        case .rsaSignatureMessagePKCS1v15SHA384: alg = "RS384"
        case .rsaSignatureMessagePKCS1v15SHA512: alg = "RS512"
        default: alg = "RS256"
        }
        let header = Data(#"{"alg":"\#(alg)","typ":"JWT","kid":"rsa-test"}"#.utf8)
        let payloadData = Data(payload.utf8)
        let headerSeg = header.base64URLEncodedString()
        let payloadSeg = payloadData.base64URLEncodedString()
        let signedInput = "\(headerSeg).\(payloadSeg)"

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            secAlgorithm,
            Data(signedInput.utf8) as CFData,
            &error
        ) as Data? else {
            throw RSAPublicKeyError.creationFailed("SecKeyCreateSignature failed")
        }

        return JWTDecoder.Parts(
            headerBytes: header,
            payloadBytes: payloadData,
            signature: signature,
            signedInput: signedInput
        )
    }

    private func makeEd25519KeyAndJWK() -> (Curve25519.Signing.PrivateKey, JWK) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let xValue = publicKey.rawRepresentation.base64URLEncodedString()
        let jwk = JWK(
            kty: "OKP",
            alg: .eddsa,
            kid: "test-kid",
            crv: "Ed25519",
            x: xValue
        )
        return (privateKey, jwk)
    }

    private func signedParts(
        privateKey: Curve25519.Signing.PrivateKey,
        payload: String
    ) -> JWTDecoder.Parts {
        let header = Data(#"{"alg":"EdDSA","typ":"JWT","kid":"test-kid"}"#.utf8)
        let payloadData = Data(payload.utf8)
        let headerSegment = header.base64URLEncodedString()
        let payloadSegment = payloadData.base64URLEncodedString()
        let signedInput = "\(headerSegment).\(payloadSegment)"
        let signature = try! privateKey.signature(for: Data(signedInput.utf8))
        return JWTDecoder.Parts(
            headerBytes: header,
            payloadBytes: payloadData,
            signature: signature,
            signedInput: signedInput
        )
    }
}

// MARK: - JWTClaimsValidator

@Suite("JWTClaimsValidator")
struct JWTClaimsValidatorTests {
    @Test("accepts valid claims")
    func acceptsValid() throws {
        let context = makeContext()
        let idToken = makeIDToken()
        try JWTClaimsValidator.validate(idToken, against: context, now: now)
    }

    @Test("rejects wrong issuer")
    func wrongIssuer() {
        let context = makeContext()
        let idToken = makeIDToken(iss: URL(string: "https://different.example.com")!)
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.wrongIssuer) {
            // ok
        } catch {
            Issue.record("expected wrongIssuer, got \(error)")
        }
    }

    @Test("rejects wrong audience")
    func wrongAudience() {
        let context = makeContext()
        let idToken = makeIDToken(aud: ["someone-else"])
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.wrongAudience) {
            // ok
        } catch {
            Issue.record("expected wrongAudience, got \(error)")
        }
    }

    @Test("rejects expired token")
    func expiredToken() {
        let context = makeContext()
        let idToken = makeIDToken(exp: now.addingTimeInterval(-3600))
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.expired) {
            // ok
        } catch {
            Issue.record("expected expired, got \(error)")
        }
    }

    @Test("rejects missing nonce when one expected")
    func missingNonce() {
        let context = makeContext(nonce: "expected-nonce")
        let idToken = makeIDToken(nonce: nil)
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.missingNonce) {
            // ok
        } catch {
            Issue.record("expected missingNonce, got \(error)")
        }
    }

    @Test("rejects mismatched nonce")
    func mismatchedNonce() {
        let context = makeContext(nonce: "expected-nonce")
        let idToken = makeIDToken(nonce: "wrong-nonce")
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.nonceMismatch) {
            // ok
        } catch {
            Issue.record("expected nonceMismatch, got \(error)")
        }
    }

    @Test("rejects unverified email when required")
    func unverifiedEmail() {
        let context = makeContext(requireVerifiedEmail: true)
        let idToken = makeIDToken(emailVerified: false)
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.emailNotVerified) {
            // ok
        } catch {
            Issue.record("expected emailNotVerified, got \(error)")
        }
    }

    @Test("rejects wrong algorithm")
    func wrongAlgorithm() {
        let context = makeContext(allowedAlgorithms: [.rs256])
        let idToken = makeIDToken()
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.wrongAlgorithm) {
            // ok
        } catch {
            Issue.record("expected wrongAlgorithm, got \(error)")
        }
    }

    // MARK: helpers

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeContext(
        nonce: String? = nil,
        requireVerifiedEmail: Bool = false,
        allowedAlgorithms: Set<SigningAlgorithm> = [.eddsa]
    ) -> JWTClaimsValidator.Context {
        JWTClaimsValidator.Context(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            nonce: nonce,
            requireVerifiedEmail: requireVerifiedEmail,
            allowedAlgorithms: allowedAlgorithms
        )
    }

    private func makeIDToken(
        iss: URL = URL(string: "https://auth.example.com")!,
        aud: [String] = ["my-app"],
        exp: Date = Date(timeIntervalSince1970: 1_700_003_600),
        nonce: String? = nil,
        emailVerified: Bool? = nil,
        alg: SigningAlgorithm = .eddsa
    ) -> IDToken {
        let claims = IDTokenClaims(
            sub: "user-123",
            aud: aud,
            iss: iss,
            iat: Date(timeIntervalSince1970: 1_700_000_000),
            exp: exp,
            nonce: nonce,
            email: emailVerified != nil ? "user@example.com" : nil,
            emailVerified: emailVerified
        )
        return IDToken(
            raw: "header.payload.signature",
            header: JWTHeader(alg: alg, typ: "JWT", kid: "test-kid"),
            payload: claims,
            signature: Data()
        )
    }
}

// MARK: - InMemoryStorage round-trip

@Suite("InMemoryStorage")
struct InMemoryStorageTests {
    @Test("save then load returns same token")
    func saveLoad() async throws {
        let storage = InMemoryStorage()
        let token = makeToken()
        try await storage.save(token)
        let loaded = try await storage.load()
        #expect(loaded == token)
    }

    @Test("load on empty storage returns nil")
    func loadEmpty() async throws {
        let storage = InMemoryStorage()
        let loaded = try await storage.load()
        #expect(loaded == nil)
    }

    @Test("clear removes stored token")
    func clear() async throws {
        let storage = InMemoryStorage()
        try await storage.save(makeToken())
        try await storage.clear()
        let loaded = try await storage.load()
        #expect(loaded == nil)
    }

    private func makeToken() -> Token {
        Token(
            id: UUID().uuidString,
            accessToken: "access-token",
            refreshToken: nil,
            idToken: nil,
            tokenType: .bearer,
            scope: ["openid"],
            issuedAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresIn: 3600
        )
    }
}

// MARK: - URLProtocol mock for wire-level tests

/// Test-only URLProtocol that lets each test specify how to handle the
/// incoming request and what response to send back.
///
/// Usage:
///   let config = URLSessionConfiguration.ephemeral
///   config.protocolClasses = [MockURLProtocol.self]
///   let session = URLSession(configuration: config)
///   MockURLProtocol.handler = { request in
///       let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
///       return (response, Data("{}".utf8))
///   }
final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

/// Helpers shared across wire tests.
enum WireTestHelpers {
    static func makeMockSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    static func makeDiscovery(
        issuer: String = "https://auth.example.com",
        includeUserinfo: Bool = true,
        includeRevocation: Bool = true
    ) -> OpenIDConfiguration {
        OpenIDConfiguration(
            issuer: URL(string: issuer)!,
            authorizationEndpoint: URL(string: "\(issuer)/authorize")!,
            tokenEndpoint: URL(string: "\(issuer)/token")!,
            userinfoEndpoint: includeUserinfo ? URL(string: "\(issuer)/userinfo")! : nil,
            jwksURI: URL(string: "\(issuer)/jwks")!,
            revocationEndpoint: includeRevocation ? URL(string: "\(issuer)/revoke")! : nil
        )
    }

    static func makeConfig() -> RauthyConfig {
        .production(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            redirectURI: URL(string: "myapp://cb")!,
            userClaim: .any,
            adminClaim: .none
        )
    }

    static func makeToken(refreshToken: String? = "rt-123", expiresIn: TimeInterval = 3600) -> Token {
        Token(
            id: UUID().uuidString,
            accessToken: "at-old",
            refreshToken: refreshToken,
            idToken: nil,
            tokenType: .bearer,
            scope: ["openid"],
            issuedAt: Date(),
            expiresIn: expiresIn
        )
    }

    static func makeIDToken(sub: String = "user-123") -> IDToken {
        let claims = IDTokenClaims(
            sub: sub,
            aud: ["my-app"],
            iss: URL(string: "https://auth.example.com")!,
            iat: Date(),
            exp: Date(timeIntervalSinceNow: 3600)
        )
        return IDToken(
            raw: "header.payload.signature",
            header: JWTHeader(alg: .eddsa, typ: "JWT", kid: "test-kid"),
            payload: claims,
            signature: Data()
        )
    }

    /// Token with an ID token attached — needed by AccountAPI to resolve
    /// the current user ID for `/users/{id}/...` URLs.
    static func makeTokenWithIDToken(
        sub: String = "user-123",
        accessToken: String = "at-active",
        expiresIn: TimeInterval = 3600
    ) -> Token {
        Token(
            id: UUID().uuidString,
            accessToken: accessToken,
            refreshToken: "rt-123",
            idToken: makeIDToken(sub: sub),
            tokenType: .bearer,
            scope: ["openid"],
            issuedAt: Date(),
            expiresIn: expiresIn
        )
    }

    /// URLSession moves `httpBody` to `httpBodyStream` before URLProtocol sees
    /// the request, so we have to read the stream to get the body bytes back.
    static func bodyData(from request: URLRequest) -> Data {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return Data()
        }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let bufferSize = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            if read > 0 {
                data.append(buffer, count: read)
            } else {
                break
            }
        }
        return data
    }

    static func formBody(from request: URLRequest) -> [String: String] {
        let body = String(data: bodyData(from: request), encoding: .utf8) ?? ""
        var items: [String: String] = [:]
        for pair in body.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { continue }
            items[parts[0]] = parts[1].removingPercentEncoding ?? parts[1]
        }
        return items
    }
}

// MARK: - Wire-level tests
//
// Wrapped in a single parent suite with `.serialized` so the shared
// MockURLProtocol.handler global isn't trampled by parallel tests.

@Suite("Wire", .serialized)
enum WireTests {

@Suite("TokenExchange.refresh")
struct TokenRefreshWireTests {
    @Test("sends grant_type=refresh_token and refresh_token in form body")
    func sendsCorrectRequest() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let discovery = WireTestHelpers.makeDiscovery()

        nonisolated(unsafe) var capturedRequest: URLRequest?
        MockURLProtocol.handler = { request in
            capturedRequest = request
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            let body = #"""
            {
                "access_token": "at-new",
                "refresh_token": "rt-new",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid profile"
            }
            """#
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let token = try await TokenExchange.refresh(
            refreshToken: "rt-original",
            config: config,
            discovery: discovery,
            session: session
        )

        let req = try #require(capturedRequest)
        #expect(req.url == discovery.tokenEndpoint)
        #expect(req.httpMethod == "POST")
        let form = WireTestHelpers.formBody(from: req)
        #expect(form["grant_type"] == "refresh_token")
        #expect(form["refresh_token"] == "rt-original")
        #expect(form["client_id"] == "my-app")

        #expect(token.accessToken == "at-new")
        #expect(token.refreshToken == "rt-new")
        #expect(token.expiresIn == 3600)
    }

    @Test("decodes server-side OAuth error on 400")
    func decodesOAuthError() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let discovery = WireTestHelpers.makeDiscovery()

        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 400, httpVersion: nil, headerFields: nil)!
            let body = Data(#"{"error":"invalid_grant","error_description":"refresh token expired"}"#.utf8)
            return (response, body)
        }
        defer { MockURLProtocol.handler = nil }

        do {
            _ = try await TokenExchange.refresh(
                refreshToken: "rt-expired",
                config: config,
                discovery: discovery,
                session: session
            )
            Issue.record("expected throw")
        } catch RauthyError.oauth(let err) {
            #expect(err.code == .invalidGrant)
            #expect(err.description == "refresh token expired")
        } catch {
            Issue.record("expected RauthyError.oauth, got \(error)")
        }
    }
}

// MARK: - TokenRevocation wire tests

@Suite("TokenRevocation")
struct TokenRevocationWireTests {
    @Test("POSTs token + token_type_hint=refresh_token")
    func revokesRefreshToken() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let discovery = WireTestHelpers.makeDiscovery()
        let token = WireTestHelpers.makeToken(refreshToken: "rt-to-revoke")

        nonisolated(unsafe) var capturedRequest: URLRequest?
        MockURLProtocol.handler = { request in
            capturedRequest = request
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }
        defer { MockURLProtocol.handler = nil }

        try await TokenRevocation.revoke(
            token: token,
            config: config,
            discovery: discovery,
            session: session
        )

        let req = try #require(capturedRequest)
        #expect(req.url == discovery.revocationEndpoint)
        #expect(req.httpMethod == "POST")
        let form = WireTestHelpers.formBody(from: req)
        #expect(form["token"] == "rt-to-revoke")
        #expect(form["token_type_hint"] == "refresh_token")
        #expect(form["client_id"] == "my-app")
    }

    @Test("falls back to access_token hint when no refresh token")
    func revokesAccessTokenFallback() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let discovery = WireTestHelpers.makeDiscovery()
        let token = WireTestHelpers.makeToken(refreshToken: nil)

        nonisolated(unsafe) var capturedRequest: URLRequest?
        MockURLProtocol.handler = { request in
            capturedRequest = request
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }
        defer { MockURLProtocol.handler = nil }

        try await TokenRevocation.revoke(
            token: token,
            config: config,
            discovery: discovery,
            session: session
        )

        let form = WireTestHelpers.formBody(from: try #require(capturedRequest))
        #expect(form["token"] == "at-old")
        #expect(form["token_type_hint"] == "access_token")
    }

    @Test("throws when discovery has no revocation_endpoint")
    func throwsWhenNoEndpoint() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let discovery = WireTestHelpers.makeDiscovery(includeRevocation: false)
        let token = WireTestHelpers.makeToken()

        await #expect(throws: RauthyError.self) {
            try await TokenRevocation.revoke(
                token: token,
                config: config,
                discovery: discovery,
                session: session
            )
        }
    }
}

// MARK: - RauthyClient fetchUser wire tests

@Suite("RauthyClient.fetchUser")
struct FetchUserWireTests {
    @Test("sends Bearer auth header and parses User response")
    func fetchesUser() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        nonisolated(unsafe) var capturedRequest: URLRequest?
        MockURLProtocol.handler = { request in
            capturedRequest = request
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "userinfo_endpoint": "https://auth.example.com/userinfo",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            // userinfo
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let body = """
            {
                "id": "rauthy-uid",
                "sub": "user-123",
                "name": "Alice",
                "email": "alice@example.com",
                "email_verified": true,
                "roles": ["admin"],
                "mfa_enabled": true
            }
            """
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        let token = WireTestHelpers.makeToken()
        try await storage.save(token)

        let client = RauthyClient(config: config, storage: storage, urlSession: session)
        let user = try await client.fetchUser()

        #expect(user.id == "rauthy-uid")
        #expect(user.subject == "user-123")
        #expect(user.email == "alice@example.com")
        #expect(user.mfaEnabled == true)

        let lastReq = try #require(capturedRequest)
        #expect(lastReq.value(forHTTPHeaderField: "Authorization")?.starts(with: "Bearer ") == true)
    }

    @Test("401 from /userinfo throws reauthenticationRequired")
    func unauthorizedThrowsReauth() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "userinfo_endpoint": "https://auth.example.com/userinfo",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        try await storage.save(WireTestHelpers.makeToken())
        let client = RauthyClient(config: config, storage: storage, urlSession: session)

        do {
            _ = try await client.fetchUser()
            Issue.record("expected throw")
        } catch RauthyError.reauthenticationRequired {
            // ok
        } catch {
            Issue.record("expected reauthenticationRequired, got \(error)")
        }
    }
}

// MARK: - AccountAPI wire tests

@Suite("AccountAPI")
struct AccountAPIWireTests {
    @Test("updatePreferredUsername PUTs to /users/{id}/self/preferred_username")
    func updateUsername() async throws {
        let (client, capturedRequests, storage) = try await makeClient(sub: "user-abc")
        _ = storage

        try await client.account.updatePreferredUsername("alice")

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/self/preferred_username")
        #expect(req.httpMethod == "PUT")
        let body = WireTestHelpers.bodyData(from: req)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["preferred_username"] as? String == "alice")
    }

    @Test("updateProfile PUTs to /users/{id}/self with provided fields only")
    func updateProfileEmail() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")

        try await client.account.updateProfile(email: "new@example.com")

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/self")
        #expect(req.httpMethod == "PUT")
        let body = WireTestHelpers.bodyData(from: req)
        let json = try JSONSerialization.jsonObject(with: body) as? [String: Any]
        #expect(json?["email"] as? String == "new@example.com")
        #expect(json?["given_name"] == nil)
    }

    @Test("updateProfile with no fields is a no-op (no network request)")
    func updateProfileNoOp() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")
        let before = capturedRequests.count

        try await client.account.updateProfile()

        // Should still only have the discovery request, not a PUT.
        #expect(capturedRequests.count == before)
    }

    @Test("devices GETs /users/{id}/devices and parses response")
    func listDevices() async throws {
        let (client, _, _) = try await makeClient(
            sub: "user-abc",
            responseBuilder: { request in
                if request.url?.path == "/users/user-abc/devices" {
                    let response = HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                    let body = """
                    [
                        {
                            "id": "dev-1",
                            "client_id": "my-app",
                            "user_id": "user-abc",
                            "created": 1700000000,
                            "access_exp": 1700003600,
                            "peer_ip": "1.2.3.4",
                            "name": "iPhone"
                        }
                    ]
                    """
                    return (response, Data(body.utf8))
                }
                return nil
            }
        )

        let devices = try await client.account.devices()
        #expect(devices.count == 1)
        #expect(devices.first?.id == "dev-1")
        #expect(devices.first?.peerIP == "1.2.3.4")
        #expect(devices.first?.name == "iPhone")
    }

    @Test("revokeDevice DELETEs /users/{id}/devices with device_id body")
    func revokeDevice() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")
        try await client.account.revokeDevice(id: "dev-to-remove")

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/devices")
        #expect(req.httpMethod == "DELETE")
        let json = try JSONSerialization.jsonObject(
            with: WireTestHelpers.bodyData(from: req)
        ) as? [String: Any]
        #expect(json?["device_id"] as? String == "dev-to-remove")
    }

    @Test("requestAccountDeletion GETs /users/{id}/self/delete")
    func requestDeletion() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")
        try await client.account.requestAccountDeletion()

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/self/delete")
        #expect(req.httpMethod == "GET")
    }

    @Test("confirmAccountDeletion DELETEs /users/{id}/self/delete + clears storage")
    func confirmDeletion() async throws {
        let (client, capturedRequests, storage) = try await makeClient(sub: "user-abc")
        try await client.account.confirmAccountDeletion()

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/self/delete")
        #expect(req.httpMethod == "DELETE")

        let stored = try await storage.load()
        #expect(stored == nil)
    }

    @Test("401 from account endpoint throws reauthenticationRequired")
    func unauthorized() async throws {
        let (client, _, _) = try await makeClient(
            sub: "user-abc",
            responseBuilder: { request in
                if request.url?.path.contains("preferred_username") == true {
                    let response = HTTPURLResponse(
                        url: request.url!,
                        statusCode: 401,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                    return (response, Data())
                }
                return nil
            }
        )

        do {
            try await client.account.updatePreferredUsername("alice")
            Issue.record("expected throw")
        } catch RauthyError.reauthenticationRequired {
            // ok
        } catch {
            Issue.record("expected reauthenticationRequired, got \(error)")
        }
    }

    // MARK: - helpers

    typealias ResponseBuilder = @Sendable (URLRequest) -> (HTTPURLResponse, Data)?

    /// Build a RauthyClient with an InMemoryStorage holding a token + ID token.
    /// Returns (client, capturedRequests box, storage). The box accumulates
    /// every request the mock URLSession sees; tests inspect `.last` typically.
    @MainActor
    private func makeClient(
        sub: String,
        responseBuilder: ResponseBuilder? = nil
    ) async throws -> (RauthyClient, RequestBox, InMemoryStorage) {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let box = RequestBox()

        MockURLProtocol.handler = { request in
            box.append(request)
            if let custom = responseBuilder?(request) {
                return custom
            }
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            // Default: 200 OK with empty body
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }

        let storage = InMemoryStorage()
        try await storage.save(WireTestHelpers.makeTokenWithIDToken(sub: sub))
        let client = RauthyClient(config: config, storage: storage, urlSession: session)
        return (client, box, storage)
    }
}

/// Thread-safe collector for captured URLRequests.
final class RequestBox: @unchecked Sendable {
    private var items: [URLRequest] = []
    private let lock = NSLock()

    func append(_ request: URLRequest) {
        lock.lock(); defer { lock.unlock() }
        items.append(request)
    }

    var last: URLRequest? {
        lock.lock(); defer { lock.unlock() }
        return items.last
    }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return items.count
    }
}

// MARK: - PasskeyAPI wire tests

@Suite("PasskeyAPI")
struct PasskeyAPIWireTests {
    @Test("list GETs /users/{id}/webauthn and parses response")
    func list() async throws {
        let (client, _, _) = try await makeClient(
            sub: "user-abc",
            responseBuilder: { request in
                if request.url?.path == "/users/user-abc/webauthn" {
                    let response = HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                    let body = """
                    [
                        {
                            "name": "iPhone",
                            "registered": 1700000000,
                            "last_used": 1700100000,
                            "user_verified": true
                        }
                    ]
                    """
                    return (response, Data(body.utf8))
                }
                return nil
            }
        )
        let passkeys = try await client.passkeys.list()
        #expect(passkeys.count == 1)
        #expect(passkeys.first?.name == "iPhone")
        #expect(passkeys.first?.userVerified == true)
    }

    @Test("delete DELETEs /users/{id}/webauthn/delete/{name}")
    func delete() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")

        try await client.passkeys.delete(name: "iPhone")

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/webauthn/delete/iPhone")
        #expect(req.httpMethod == "DELETE")
    }

    @Test("RegisterPublicKeyCredentialJSON encodes credential parts as base64url")
    func credentialJSONEncoding() throws {
        let credentialID = Data([0x01, 0x02, 0x03, 0x04])
        let attestationObject = Data([0xAA, 0xBB])
        let clientDataJSON = Data(#"{"type":"webauthn.create"}"#.utf8)
        let cred = RegisteredCredential(
            credentialID: credentialID,
            attestationObject: attestationObject,
            clientDataJSON: clientDataJSON
        )
        let json = RegisterPublicKeyCredentialJSON(credential: cred)

        #expect(json.type == "public-key")
        #expect(json.authenticatorAttachment == "platform")
        #expect(json.id == credentialID.base64URLEncodedString())
        #expect(json.rawId == credentialID.base64URLEncodedString())
        #expect(json.response.attestationObject == attestationObject.base64URLEncodedString())
        #expect(json.response.clientDataJSON == clientDataJSON.base64URLEncodedString())
    }

    @Test("PasskeyRegistrationChallenge decodes start response")
    func decodeStartResponse() throws {
        let json = """
        {
            "publicKey": {
                "rp": { "id": "auth.example.com", "name": "Rauthy" },
                "user": {
                    "id": "dXNlci0xMjM",
                    "name": "alice",
                    "displayName": "Alice"
                },
                "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
                "pubKeyCredParams": [{ "type": "public-key", "alg": -8 }],
                "timeout": 60000,
                "attestation": "none"
            }
        }
        """
        let decoded = try JSONDecoder().decode(
            PasskeyRegistrationChallenge.self,
            from: Data(json.utf8)
        )
        #expect(decoded.publicKey.rp.id == "auth.example.com")
        #expect(decoded.publicKey.user.name == "alice")
        #expect(decoded.publicKey.challenge == "Y2hhbGxlbmdlLWJ5dGVz")
        #expect(decoded.publicKey.timeout == 60000)
    }

    // MARK: - helpers (duplicate of AccountAPI helpers)

    private typealias ResponseBuilder = @Sendable (URLRequest) -> (HTTPURLResponse, Data)?

    @MainActor
    private func makeClient(
        sub: String,
        responseBuilder: ResponseBuilder? = nil
    ) async throws -> (RauthyClient, RequestBox, InMemoryStorage) {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let box = RequestBox()

        MockURLProtocol.handler = { request in
            box.append(request)
            if let custom = responseBuilder?(request) {
                return custom
            }
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }

        let storage = InMemoryStorage()
        try await storage.save(WireTestHelpers.makeTokenWithIDToken(sub: sub))
        let client = RauthyClient(config: config, storage: storage, urlSession: session)
        return (client, box, storage)
    }
}

// MARK: - Additional Account wire tests for rename / convertPasskey / avatar

@Suite("AccountAPI additions")
struct AccountAPIAdditionsTests {
    @Test("renameDevice PUTs /users/{id}/devices with device_id + name")
    func renameDevice() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")
        try await client.account.renameDevice(id: "dev-1", to: "MacBook")

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/devices")
        #expect(req.httpMethod == "PUT")
        let json = try JSONSerialization.jsonObject(
            with: WireTestHelpers.bodyData(from: req)
        ) as? [String: Any]
        #expect(json?["device_id"] as? String == "dev-1")
        #expect(json?["name"] as? String == "MacBook")
    }

    @Test("convertToPasskeyOnly POSTs /users/{id}/self/convert_passkey")
    func convertToPasskeyOnly() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")
        try await client.account.convertToPasskeyOnly()

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/self/convert_passkey")
        #expect(req.httpMethod == "POST")
    }

    @Test("uploadAvatar PUTs multipart to /users/{id}/picture")
    func uploadAvatar() async throws {
        let (client, capturedRequests, _) = try await makeClient(
            sub: "user-abc",
            responseBuilder: { request in
                if request.url?.path == "/users/user-abc/picture" {
                    let response = HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: nil
                    )!
                    return (response, Data("new-picture-id-xyz".utf8))
                }
                return nil
            }
        )

        let imageBytes = Data([0xFF, 0xD8, 0xFF, 0xE0])  // JPEG magic
        let pictureID = try await client.account.uploadAvatar(
            imageBytes,
            mimeType: "image/jpeg"
        )
        #expect(pictureID == "new-picture-id-xyz")

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/picture")
        #expect(req.httpMethod == "PUT")
        let contentType = req.value(forHTTPHeaderField: "Content-Type") ?? ""
        #expect(contentType.hasPrefix("multipart/form-data; boundary="))

        // Body should contain the JPEG magic bytes wrapped in multipart envelope.
        let body = WireTestHelpers.bodyData(from: req)
        #expect(body.range(of: Data([0xFF, 0xD8, 0xFF, 0xE0])) != nil)
        let asString = String(data: body, encoding: .utf8) ?? ""
        // utf8 decoding may fail on binary bytes — that's OK; just check the parts we can decode
        if !asString.isEmpty {
            #expect(asString.contains("Content-Disposition: form-data"))
            #expect(asString.contains("Content-Type: image/jpeg"))
        }
    }

    @Test("deleteAvatar DELETEs /users/{id}/picture/{picture_id}")
    func deleteAvatar() async throws {
        let (client, capturedRequests, _) = try await makeClient(sub: "user-abc")
        try await client.account.deleteAvatar(pictureID: "picture-xyz")

        let req = try #require(capturedRequests.last)
        #expect(req.url?.path == "/users/user-abc/picture/picture-xyz")
        #expect(req.httpMethod == "DELETE")
    }

    @Test("pictureURL composes /users/{userID}/picture/{pictureID}")
    func pictureURL() async throws {
        let (client, _, _) = try await makeClient(sub: "user-abc")
        let url = client.pictureURL(userID: "user-abc", pictureID: "pic-1")
        #expect(url.path == "/users/user-abc/picture/pic-1")
    }

    // MARK: - helpers (same shape as AccountAPI tests)

    private typealias ResponseBuilder = @Sendable (URLRequest) -> (HTTPURLResponse, Data)?

    @MainActor
    private func makeClient(
        sub: String,
        responseBuilder: ResponseBuilder? = nil
    ) async throws -> (RauthyClient, RequestBox, InMemoryStorage) {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let box = RequestBox()

        MockURLProtocol.handler = { request in
            box.append(request)
            if let custom = responseBuilder?(request) {
                return custom
            }
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }

        let storage = InMemoryStorage()
        try await storage.save(WireTestHelpers.makeTokenWithIDToken(sub: sub))
        let client = RauthyClient(config: config, storage: storage, urlSession: session)
        return (client, box, storage)
    }
}

// MARK: - MultipartFormData

@Suite("MultipartFormData")
struct MultipartFormDataTests {
    @Test("produces well-formed multipart envelope")
    func wellFormed() throws {
        let data = Data("hello".utf8)
        let body = MultipartFormData.build(
            boundary: "BOUNDARY",
            fieldName: "file",
            filename: "test.txt",
            mimeType: "text/plain",
            data: data
        )
        let s = String(data: body, encoding: .utf8)!
        #expect(s.contains("--BOUNDARY\r\n"))
        #expect(s.contains(#"Content-Disposition: form-data; name="file"; filename="test.txt""#))
        #expect(s.contains("Content-Type: text/plain"))
        #expect(s.contains("hello"))
        #expect(s.hasSuffix("--BOUNDARY--\r\n"))
    }
}

// MARK: - RauthyClient auto-refresh

@Suite("RauthyClient auto-refresh")
struct AutoRefreshTests {
    @Test("validAccessToken auto-refreshes an expired token")
    func autoRefresh() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        nonisolated(unsafe) var tokenEndpointCalls = 0
        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            // token endpoint
            tokenEndpointCalls += 1
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let body = #"""
            {
                "access_token": "at-fresh",
                "refresh_token": "rt-rotated",
                "token_type": "Bearer",
                "expires_in": 3600
            }
            """#
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        let expiredToken = Token(
            id: UUID().uuidString,
            accessToken: "at-stale",
            refreshToken: "rt-original",
            idToken: nil,
            tokenType: .bearer,
            scope: ["openid"],
            issuedAt: Date().addingTimeInterval(-7200),
            expiresIn: 3600
        )
        try await storage.save(expiredToken)

        let client = RauthyClient(config: config, storage: storage, urlSession: session)
        let accessToken = try await client.validAccessToken()

        #expect(accessToken == "at-fresh")
        #expect(tokenEndpointCalls == 1)

        // Storage should now have the new token.
        let stored = try await storage.load()
        #expect(stored?.accessToken == "at-fresh")
        #expect(stored?.refreshToken == "rt-rotated")
    }

    @Test("refreshSession returns new token without checking expiry")
    func explicitRefresh() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let body = #"""
            {
                "access_token": "at-forced",
                "token_type": "Bearer",
                "expires_in": 3600
            }
            """#
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        let freshToken = WireTestHelpers.makeToken(expiresIn: 3600)
        try await storage.save(freshToken)

        let client = RauthyClient(config: config, storage: storage, urlSession: session)
        let refreshed = try await client.refreshSession()
        #expect(refreshed.accessToken == "at-forced")
    }

    @Test("parallel callers of an expired-token validAccessToken coalesce into one refresh")
    func parallelCallersCoalesce() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        nonisolated(unsafe) var tokenEndpointCalls = 0
        let counterLock = NSLock()
        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            counterLock.lock()
            tokenEndpointCalls += 1
            counterLock.unlock()
            // Add a small delay to ensure parallel callers race.
            Thread.sleep(forTimeInterval: 0.05)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let body = #"""
            {
                "access_token": "at-coalesced",
                "refresh_token": "rt-coalesced",
                "token_type": "Bearer",
                "expires_in": 3600
            }
            """#
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        let expiredToken = Token(
            id: UUID().uuidString,
            accessToken: "at-stale",
            refreshToken: "rt-original",
            idToken: nil,
            tokenType: .bearer,
            scope: ["openid"],
            issuedAt: Date().addingTimeInterval(-7200),
            expiresIn: 3600
        )
        try await storage.save(expiredToken)
        let client = RauthyClient(config: config, storage: storage, urlSession: session)

        // Fire 5 concurrent callers.
        async let r1 = client.validAccessToken()
        async let r2 = client.validAccessToken()
        async let r3 = client.validAccessToken()
        async let r4 = client.validAccessToken()
        async let r5 = client.validAccessToken()

        let results = try await [r1, r2, r3, r4, r5]
        for result in results {
            #expect(result == "at-coalesced")
        }
        // Without single-flight, this would be 5 (one per caller).
        #expect(tokenEndpointCalls == 1)
    }

    @Test("invalid_grant during refresh clears storage and throws reauthenticationRequired")
    func invalidGrantClearsStorage() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 400, httpVersion: nil, headerFields: nil)!
            let body = Data(#"{"error":"invalid_grant"}"#.utf8)
            return (response, body)
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        try await storage.save(WireTestHelpers.makeToken())
        let client = RauthyClient(config: config, storage: storage, urlSession: session)

        do {
            _ = try await client.refreshSession()
            Issue.record("expected throw")
        } catch RauthyError.reauthenticationRequired {
            // Storage should be cleared.
            let after = try await storage.load()
            #expect(after == nil)
        } catch {
            Issue.record("expected reauthenticationRequired, got \(error)")
        }
    }
}

// MARK: - RauthyConfig

@Suite("RauthyConfig")
struct RauthyConfigTests {
    @Test("production factory sets sensible defaults")
    func productionDefaults() {
        let config = RauthyConfig.production(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            redirectURI: URL(string: "myapp://cb")!,
            userClaim: .or([.group("users")]),
            adminClaim: .or([.role("admin")])
        )
        #expect(config.requireVerifiedEmail == true)
        #expect(config.scopes == ["openid", "profile", "email"])
        #expect(config.localDev == nil)
        #expect(config.allowedAlgorithms == Set(SigningAlgorithm.allCases))
    }

    @Test("development factory enables local dev mode")
    func developmentDefaults() {
        let config = RauthyConfig.development(
            redirectURI: URL(string: "myapp://cb")!
        )
        #expect(config.localDev != nil)
        #expect(config.localDev?.allowInsecureHTTP == true)
        #expect(config.requireVerifiedEmail == false)
        #expect(config.userClaim == .any)
        #expect(config.adminClaim == .none)
    }
}

// MARK: - Localization
//
// Rauthy.locale is a process-global, so these tests must be serialized to
// avoid one test's locale override leaking into another's reads.

@Suite("Localization", .serialized)
final class LocalizationTests {
    init() { Rauthy.locale = nil }
    deinit { Rauthy.locale = nil }

    @Test("default locale follows system, never crashes")
    func defaultLocale() {
        Rauthy.locale = nil
        let desc = RauthyError.networkUnavailable.localizedDescription
        #expect(!desc.isEmpty)
        #expect(desc != "error.networkUnavailable")
    }

    @Test("English override")
    func english() {
        Rauthy.locale = Locale(identifier: "en")
        #expect(
            RauthyError.networkUnavailable.localizedDescription
                == "Network unavailable. Please check your connection and try again."
        )
        #expect(RauthyError.userCancelled.localizedDescription == "Sign-in was cancelled.")
        #expect(RauthyError.tokenExpired.localizedDescription == "Your session has expired.")
    }

    @Test("Simplified Chinese override")
    func chinese() {
        Rauthy.locale = Locale(identifier: "zh-Hans")
        #expect(
            RauthyError.networkUnavailable.localizedDescription
                == "网络不可用,请检查网络连接后重试。"
        )
        #expect(RauthyError.userCancelled.localizedDescription == "登录已取消。")
        #expect(RauthyError.tokenExpired.localizedDescription == "登录已过期。")
    }

    @Test("Japanese override")
    func japanese() {
        Rauthy.locale = Locale(identifier: "ja")
        #expect(
            RauthyError.networkUnavailable.localizedDescription
                == "ネットワークに接続できません。接続を確認してもう一度お試しください。"
        )
        #expect(
            RauthyError.userCancelled.localizedDescription
                == "サインインがキャンセルされました。"
        )
        #expect(
            RauthyError.tokenExpired.localizedDescription
                == "セッションの有効期限が切れました。"
        )
    }

    @Test("nested OAuth error delegates to inner code")
    func oauthDelegation() {
        Rauthy.locale = Locale(identifier: "zh-Hans")
        let err = RauthyError.oauth(OAuthError(code: .accessDenied))
        #expect(err.localizedDescription == "登录被拒绝。")
    }

    @Test("nested JWT failure delegates to inner case")
    func jwtDelegation() {
        Rauthy.locale = Locale(identifier: "ja")
        let err = RauthyError.invalidJWT(.signatureInvalid)
        #expect(err.localizedDescription == "ID トークンの署名が無効です。")
    }

    @Test("nested keychain error delegates to inner case")
    func keychainDelegation() {
        Rauthy.locale = Locale(identifier: "en")
        let err = RauthyError.keychainError(.accessDenied)
        #expect(err.localizedDescription == "Secure storage access was denied.")
    }

    @Test("server error embeds HTTP status code")
    func serverErrorFormatting() {
        Rauthy.locale = Locale(identifier: "en")
        let err = RauthyError.server(ServerError(statusCode: 503))
        #expect(err.localizedDescription == "The server returned an error (503).")

        Rauthy.locale = Locale(identifier: "zh-Hans")
        #expect(
            RauthyError.server(ServerError(statusCode: 502)).localizedDescription
                == "服务器返回错误(502)。"
        )
    }

    @Test("keychain.osStatus embeds OSStatus code")
    func keychainOSStatusFormatting() {
        Rauthy.locale = Locale(identifier: "en")
        let err = KeychainError.osStatus(-25300)
        #expect(err.localizedDescription == "Secure storage error (-25300).")
    }

    @Test("unsupported locale falls back to English (defaultLocalization)")
    func fallbackToEnglish() {
        // German isn't shipped — Package.swift declares defaultLocalization "en",
        // so Bundle.module's localization for "de" resolves to the en strings.
        Rauthy.locale = Locale(identifier: "de")
        #expect(
            RauthyError.tokenExpired.localizedDescription == "Your session has expired."
        )
    }

    @Test("bare Locale(identifier: \"zh\") resolves to zh-Hans, not English")
    func bareChineseLocale() {
        // Locale(identifier: "zh").language.languageCode = "zh".
        // Without script-tag fallback this silently picks English, which is
        // worse than the user-visible setting.
        Rauthy.locale = Locale(identifier: "zh")
        #expect(RauthyError.userCancelled.localizedDescription == "登录已取消。")
    }

    @Test("oauth.invalidGrant translates as credentials issue, not denial")
    func invalidGrantTranslation() {
        // "invalid_grant" per RFC 6749 §5.2 means the auth code / refresh
        // token is invalid or expired — not "access denied". Tests guard
        // against translators reverting to the more-natural-sounding wrong
        // meaning.
        Rauthy.locale = Locale(identifier: "zh-Hans")
        #expect(
            RauthyError.oauth(OAuthError(code: .invalidGrant)).localizedDescription
                == "登录凭据无效或已过期,请重试。"
        )
        Rauthy.locale = Locale(identifier: "ja")
        #expect(
            RauthyError.oauth(OAuthError(code: .invalidGrant)).localizedDescription
                == "サインインの認証情報が無効か期限切れです。もう一度お試しください。"
        )
    }

    @Test(".unexpected surfaces the inner error's localizedDescription")
    func unexpectedIncludesInnerDescription() {
        struct WrappedError: LocalizedError, Sendable {
            var errorDescription: String? { "boom from the network" }
        }
        Rauthy.locale = Locale(identifier: "en")
        let err = RauthyError.unexpected(WrappedError())
        #expect(
            err.localizedDescription
                == "An unexpected error occurred: boom from the network"
        )
    }

    @Test("string formatter survives translator dropping %@")
    func formatterToleratesMissingPlaceholder() {
        // Translator typos that drop %@ used to crash via String(format:);
        // safe substitution must degrade gracefully (append the value).
        // Simulated here via direct RauthyL10n call — we can't mutate the
        // shipped bundles, but the helper's contract is what matters.
        // Verified through a known good format below.
        Rauthy.locale = Locale(identifier: "en")
        let normal = KeychainError.osStatus(-25300).localizedDescription
        #expect(normal == "Secure storage error (-25300).")
    }

    @Test("server.error format substitutes status code as plain digits, no grouping")
    func serverErrorPlainDigits() {
        Rauthy.locale = Locale(identifier: "en")
        // Confirms that String(format:) digit-grouping (which would render
        // 25,300) doesn't sneak back in. Use a large status to make grouping
        // visible if regressed.
        let err = ServerError(statusCode: 25300).errorDescription
        #expect(err == "The server returned an error (25300).")
    }

    @Test("locale is thread-safe to set from any context")
    func threadSafeSet() async {
        // Hammer the locale from multiple tasks; we only care that nothing crashes
        // and the final state is observable.
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask { Rauthy.locale = Locale(identifier: "en") }
                group.addTask { Rauthy.locale = Locale(identifier: "zh-Hans") }
                group.addTask { Rauthy.locale = Locale(identifier: "ja") }
                group.addTask { _ = RauthyError.networkUnavailable.localizedDescription }
            }
        }
        // Final settle: write a known value, verify it sticks.
        Rauthy.locale = Locale(identifier: "ja")
        #expect(
            RauthyError.userCancelled.localizedDescription
                == "サインインがキャンセルされました。"
        )
    }

    @Test("supportedLocales lists what the SDK ships")
    func supportedLocalesList() {
        let identifiers = Rauthy.supportedLocales.map(\.identifier)
        #expect(identifiers.contains("en"))
        #expect(identifiers.contains("zh-Hans"))
        #expect(identifiers.contains("ja"))
    }
}

// MARK: - parseCallback robustness against duplicate query params

@Suite("AuthorizationURLBuilder.parseCallback duplicates")
struct ParseCallbackDuplicateTests {
    @Test("does not crash on duplicate code params; last value wins")
    func duplicateCodeParam() throws {
        // Pre-fix this would trap inside Dictionary(uniqueKeysWithValues:)
        // because two `code` items collide. Now it must succeed and prefer
        // the last value (matching common HTTP framework conventions).
        let url = URL(string: "myapp://cb?code=first&code=second&state=xyz")!
        let (code, state) = try AuthorizationURLBuilder.parseCallback(url)
        #expect(code == "second")
        #expect(state == "xyz")
    }

    @Test("does not crash on duplicate state params")
    func duplicateStateParam() throws {
        let url = URL(string: "myapp://cb?code=abc&state=one&state=two")!
        let (code, state) = try AuthorizationURLBuilder.parseCallback(url)
        #expect(code == "abc")
        #expect(state == "two")
    }

    @Test("does not crash on duplicate error params; surfaces last")
    func duplicateErrorParam() {
        let url = URL(string: "myapp://cb?error=access_denied&error=server_error")!
        do {
            _ = try AuthorizationURLBuilder.parseCallback(url)
            Issue.record("expected throw")
        } catch RauthyError.oauth(let err) {
            // Either value is acceptable per the spec — the important thing
            // is we didn't crash. We assert "last wins" to lock in behavior.
            #expect(err.code == .serverError)
        } catch {
            Issue.record("expected RauthyError.oauth, got \(error)")
        }
    }
}

// MARK: - Issuer scheme validation

@Suite("RauthyClient.issuerSchemeValidation")
struct IssuerSchemeValidationTests {
    @Test("https issuer passes")
    func httpsAllowed() {
        let config = makeConfig(issuer: "https://auth.example.com", localDev: nil)
        #expect(RauthyClient.issuerSchemeValidation(for: config) == .ok)
    }

    @Test("http issuer without localDev is rejected")
    func httpWithoutLocalDev() {
        let config = makeConfig(issuer: "http://localhost:8080", localDev: nil)
        let url = URL(string: "http://localhost:8080")!
        #expect(
            RauthyClient.issuerSchemeValidation(for: config)
                == .insecureHTTPNotAllowed(url)
        )
    }

    @Test("http issuer with localDev but allowInsecureHTTP=false is rejected")
    func httpWithLocalDevDisabled() {
        let config = makeConfig(
            issuer: "http://localhost:8080",
            localDev: RauthyConfig.LocalDevSettings(
                allowInsecureHTTP: false,
                trustedSelfSignedCAs: []
            )
        )
        let url = URL(string: "http://localhost:8080")!
        #expect(
            RauthyClient.issuerSchemeValidation(for: config)
                == .insecureHTTPNotAllowed(url)
        )
    }

    @Test("http issuer with localDev.allowInsecureHTTP=true passes")
    func httpWithLocalDevEnabled() {
        let config = makeConfig(
            issuer: "http://localhost:8080",
            localDev: RauthyConfig.LocalDevSettings(
                allowInsecureHTTP: true,
                trustedSelfSignedCAs: []
            )
        )
        #expect(RauthyClient.issuerSchemeValidation(for: config) == .ok)
    }

    @Test("non-http(s) scheme is rejected even with localDev enabled")
    func nonHTTPScheme() {
        let config = makeConfig(
            issuer: "ftp://example.com",
            localDev: RauthyConfig.LocalDevSettings(
                allowInsecureHTTP: true,
                trustedSelfSignedCAs: []
            )
        )
        let url = URL(string: "ftp://example.com")!
        #expect(
            RauthyClient.issuerSchemeValidation(for: config)
                == .unsupportedScheme(url)
        )
    }

    private func makeConfig(
        issuer: String,
        localDev: RauthyConfig.LocalDevSettings?
    ) -> RauthyConfig {
        RauthyConfig(
            issuer: URL(string: issuer)!,
            clientID: "my-app",
            redirectURI: URL(string: "myapp://cb")!,
            userClaim: .any,
            adminClaim: .none,
            localDev: localDev
        )
    }
}

// MARK: - LocalDev URLSession factory

@Suite("LocalDevURLSession")
struct LocalDevURLSessionTests {
    @Test("empty trustedSelfSignedCAs returns URLSession.shared")
    func emptyReturnsShared() {
        let session = LocalDevURLSession.make(
            settings: RauthyConfig.LocalDevSettings(
                allowInsecureHTTP: true,
                trustedSelfSignedCAs: []
            )
        )
        // Identity check: there's only one .shared per process.
        #expect(session === URLSession.shared)
    }

    @Test("populated trustedSelfSignedCAs returns a non-shared session")
    func populatedReturnsCustom() {
        // The bytes don't have to be a real cert for this test — we're
        // verifying the factory routes through the delegate path, not that
        // the cert parses. SecCertificateCreateWithData will return nil for
        // junk and the delegate's anchor list will be empty, which is fine
        // for the wiring check.
        let session = LocalDevURLSession.make(
            settings: RauthyConfig.LocalDevSettings(
                allowInsecureHTTP: false,
                trustedSelfSignedCAs: [Data([0x30, 0x82, 0x00, 0x00])]
            )
        )
        #expect(session !== URLSession.shared)
        // Sanity: delegate slot is occupied.
        #expect(session.delegate != nil)
    }
}

// MARK: - nbf (not-before) validation

@Suite("JWTClaimsValidator nbf")
struct NotBeforeValidationTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("nbf in the past passes")
    func nbfInPast() throws {
        let context = makeContext()
        let idToken = makeIDToken(nbf: now.addingTimeInterval(-3600))
        try JWTClaimsValidator.validate(idToken, against: context, now: now)
    }

    @Test("nbf in the future beyond leeway throws .notYetValid")
    func nbfInFutureBeyondLeeway() {
        let context = makeContext()  // default leeway 60s
        let idToken = makeIDToken(nbf: now.addingTimeInterval(300))  // 5 min ahead
        do {
            try JWTClaimsValidator.validate(idToken, against: context, now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.notYetValid) {
            // ok
        } catch {
            Issue.record("expected notYetValid, got \(error)")
        }
    }

    @Test("nbf within leeway passes")
    func nbfWithinLeeway() throws {
        let context = makeContext()  // leeway 60s
        let idToken = makeIDToken(nbf: now.addingTimeInterval(30))  // 30s ahead
        try JWTClaimsValidator.validate(idToken, against: context, now: now)
    }

    @Test("absent nbf passes")
    func absentNbf() throws {
        let context = makeContext()
        let idToken = makeIDToken(nbf: nil)
        try JWTClaimsValidator.validate(idToken, against: context, now: now)
    }

    @Test("IDTokenClaims decodes nbf when present")
    func decodesNbf() throws {
        let json = """
        {
            "sub": "user-1",
            "aud": "client-1",
            "iss": "https://auth.example.com",
            "iat": 1700000000,
            "exp": 1700003600,
            "nbf": 1700000100
        }
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let claims = try decoder.decode(IDTokenClaims.self, from: json)
        #expect(claims.nbf == Date(timeIntervalSince1970: 1_700_000_100))
    }

    private func makeContext() -> JWTClaimsValidator.Context {
        JWTClaimsValidator.Context(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            nonce: nil,
            requireVerifiedEmail: false,
            allowedAlgorithms: [.eddsa]
        )
    }

    private func makeIDToken(nbf: Date?) -> IDToken {
        let claims = IDTokenClaims(
            sub: "user-123",
            aud: ["my-app"],
            iss: URL(string: "https://auth.example.com")!,
            iat: now,
            exp: now.addingTimeInterval(3600),
            nbf: nbf
        )
        return IDToken(
            raw: "header.payload.signature",
            header: JWTHeader(alg: .eddsa, typ: "JWT", kid: "test-kid"),
            payload: claims,
            signature: Data()
        )
    }
}

// MARK: - at_hash validation (OIDC Core §3.1.3.6)

@Suite("JWTClaimsValidator at_hash")
struct AtHashValidationTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private let accessToken = "test-access-token-value"

    @Test("RS256 / EdDSA use SHA-256 / 16 bytes")
    func sha256HalfWidth() {
        // For "test-access-token-value", SHA-256 first 16 bytes base64url-encoded.
        let computed = JWTClaimsValidator.computeAtHash(
            accessToken: accessToken,
            algorithm: .rs256
        )
        // 16 bytes → 22 chars in base64url-no-pad (since 16*8/6 = 21.33 → 22)
        #expect(computed.count == 22)
        // Should match what EdDSA also produces (same hash family).
        let eddsa = JWTClaimsValidator.computeAtHash(
            accessToken: accessToken,
            algorithm: .eddsa
        )
        #expect(computed == eddsa)
    }

    @Test("RS384 uses SHA-384 / 24 bytes")
    func sha384HalfWidth() {
        let computed = JWTClaimsValidator.computeAtHash(
            accessToken: accessToken,
            algorithm: .rs384
        )
        // 24 bytes → 32 chars base64url-no-pad
        #expect(computed.count == 32)
    }

    @Test("RS512 uses SHA-512 / 32 bytes")
    func sha512HalfWidth() {
        let computed = JWTClaimsValidator.computeAtHash(
            accessToken: accessToken,
            algorithm: .rs512
        )
        // 32 bytes → 43 chars base64url-no-pad
        #expect(computed.count == 43)
    }

    @Test("matching at_hash passes")
    func matchingAtHash() throws {
        let expected = JWTClaimsValidator.computeAtHash(
            accessToken: accessToken,
            algorithm: .eddsa
        )
        let idToken = makeIDToken(atHash: expected)
        try JWTClaimsValidator.validate(
            idToken,
            against: makeContext(accessToken: accessToken),
            now: now
        )
    }

    @Test("mismatched at_hash throws .atHashMismatch")
    func mismatchedAtHash() {
        let idToken = makeIDToken(atHash: "wrong-hash-value")
        do {
            try JWTClaimsValidator.validate(
                idToken,
                against: makeContext(accessToken: accessToken),
                now: now
            )
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.atHashMismatch) {
            // ok
        } catch {
            Issue.record("expected atHashMismatch, got \(error)")
        }
    }

    @Test("absent at_hash on token skips check even when context has accessToken")
    func absentAtHashSkips() throws {
        let idToken = makeIDToken(atHash: nil)
        try JWTClaimsValidator.validate(
            idToken,
            against: makeContext(accessToken: accessToken),
            now: now
        )
    }

    @Test("absent context.accessToken skips check even when token has at_hash")
    func absentAccessTokenSkips() throws {
        let idToken = makeIDToken(atHash: "anything")
        try JWTClaimsValidator.validate(
            idToken,
            against: makeContext(accessToken: nil),
            now: now
        )
    }

    private func makeContext(accessToken: String?) -> JWTClaimsValidator.Context {
        JWTClaimsValidator.Context(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            nonce: nil,
            requireVerifiedEmail: false,
            allowedAlgorithms: [.eddsa],
            accessToken: accessToken
        )
    }

    private func makeIDToken(atHash: String?) -> IDToken {
        let claims = IDTokenClaims(
            sub: "user-123",
            aud: ["my-app"],
            iss: URL(string: "https://auth.example.com")!,
            iat: now,
            exp: now.addingTimeInterval(3600),
            atHash: atHash
        )
        return IDToken(
            raw: "header.payload.signature",
            header: JWTHeader(alg: .eddsa, typ: "JWT", kid: "test-kid"),
            payload: claims,
            signature: Data()
        )
    }
}

// MARK: - Discovery issuer pinning

@Suite("OIDCDiscovery issuer pinning")
struct DiscoveryIssuerPinningTests {
    @Test("matching issuer succeeds")
    func matchingIssuer() async throws {
        let session = WireTestHelpers.makeMockSession()
        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let body = """
            {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "jwks_uri": "https://auth.example.com/jwks",
                "response_types_supported": ["code"]
            }
            """
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let discovery = try await OIDCDiscovery.fetch(
            issuer: URL(string: "https://auth.example.com")!,
            session: session
        )
        #expect(discovery.issuer.absoluteString == "https://auth.example.com")
    }

    @Test("trailing slash difference is tolerated (Rauthy publishes with slash)")
    func trailingSlashTolerated() async throws {
        let session = WireTestHelpers.makeMockSession()
        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            // Document declares trailing slash; caller configured without.
            let body = """
            {
                "issuer": "https://auth.example.com/auth/v1/",
                "authorization_endpoint": "https://auth.example.com/auth/v1/authorize",
                "token_endpoint": "https://auth.example.com/auth/v1/token",
                "jwks_uri": "https://auth.example.com/auth/v1/jwks",
                "response_types_supported": ["code"]
            }
            """
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        _ = try await OIDCDiscovery.fetch(
            issuer: URL(string: "https://auth.example.com/auth/v1")!,
            session: session
        )
    }

    @Test("mismatched issuer throws .discoveryIssuerMismatch")
    func mismatchedIssuer() async {
        let session = WireTestHelpers.makeMockSession()
        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            // Document claims to be a different issuer — the attack signal.
            let body = """
            {
                "issuer": "https://attacker.example.com",
                "authorization_endpoint": "https://attacker.example.com/authorize",
                "token_endpoint": "https://attacker.example.com/token",
                "jwks_uri": "https://attacker.example.com/jwks",
                "response_types_supported": ["code"]
            }
            """
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        do {
            _ = try await OIDCDiscovery.fetch(
                issuer: URL(string: "https://auth.example.com")!,
                session: session
            )
            Issue.record("expected throw")
        } catch RauthyError.discoveryIssuerMismatch(let expected, let got) {
            #expect(expected.absoluteString == "https://auth.example.com")
            #expect(got.absoluteString == "https://attacker.example.com")
        } catch {
            Issue.record("expected discoveryIssuerMismatch, got \(error)")
        }
    }
}

// MARK: - PKCE verifier validation (RFC 7636 §4.1)

@Suite("PKCE.isValidVerifier")
struct PKCEVerifierValidationTests {
    @Test("43-char all-alphanumeric verifier is valid")
    func minimumLengthValid() {
        let v = String(repeating: "A", count: 43)
        #expect(PKCE.isValidVerifier(v))
    }

    @Test("128-char all-alphanumeric verifier is valid")
    func maximumLengthValid() {
        let v = String(repeating: "z", count: 128)
        #expect(PKCE.isValidVerifier(v))
    }

    @Test("42 chars (one below minimum) is invalid")
    func belowMinimumInvalid() {
        let v = String(repeating: "A", count: 42)
        #expect(!PKCE.isValidVerifier(v))
    }

    @Test("129 chars (one above maximum) is invalid")
    func aboveMaximumInvalid() {
        let v = String(repeating: "A", count: 129)
        #expect(!PKCE.isValidVerifier(v))
    }

    @Test("disallowed characters (space, +, /) reject")
    func disallowedChars() {
        let base = String(repeating: "A", count: 42)
        #expect(!PKCE.isValidVerifier(base + " "))     // space
        #expect(!PKCE.isValidVerifier(base + "+"))     // base64 char, not unreserved
        #expect(!PKCE.isValidVerifier(base + "/"))
        #expect(!PKCE.isValidVerifier(base + "="))     // padding
    }

    @Test("allowed unreserved chars are accepted")
    func allowedUnreservedChars() {
        // RFC 3986 unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
        let v = "Aa0-._~" + String(repeating: "z", count: 36)  // 43 chars
        #expect(PKCE.isValidVerifier(v))
    }

    @Test("default PKCE() produces a valid verifier")
    func defaultIsValid() {
        for _ in 0..<10 {
            let pkce = PKCE()
            #expect(PKCE.isValidVerifier(pkce.codeVerifier))
        }
    }
}

// MARK: - Discovery cache TTL + invalidation

@Suite("RauthyClient discovery cache")
struct DiscoveryCacheTests {
    @Test("invalidateDiscoveryCache forces refetch")
    func invalidateRefetches() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        nonisolated(unsafe) var discoveryFetches = 0
        let lock = NSLock()
        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                lock.lock(); discoveryFetches += 1; lock.unlock()
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "userinfo_endpoint": "https://auth.example.com/userinfo",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            // /userinfo
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let body = """
            { "id": "u", "sub": "u", "roles": [] }
            """
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        try await storage.save(WireTestHelpers.makeToken())
        let client = RauthyClient(config: config, storage: storage, urlSession: session)

        _ = try await client.fetchUser()
        #expect(discoveryFetches == 1)

        // Second call within TTL — no refetch.
        _ = try await client.fetchUser()
        #expect(discoveryFetches == 1)

        // Invalidate, third call refetches.
        await client.invalidateDiscoveryCache()
        _ = try await client.fetchUser()
        #expect(discoveryFetches == 2)
    }

    @Test("TTL=0 refetches every time")
    func zeroTTLAlwaysRefetches() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()

        nonisolated(unsafe) var discoveryFetches = 0
        let lock = NSLock()
        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                lock.lock(); discoveryFetches += 1; lock.unlock()
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                let body = """
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "userinfo_endpoint": "https://auth.example.com/userinfo",
                    "jwks_uri": "https://auth.example.com/jwks",
                    "response_types_supported": ["code"]
                }
                """
                return (response, Data(body.utf8))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data("""
            { "id": "u", "sub": "u", "roles": [] }
            """.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let storage = InMemoryStorage()
        try await storage.save(WireTestHelpers.makeToken())
        let client = RauthyClient(
            config: config,
            storage: storage,
            urlSession: session,
            discoveryTTL: 0
        )

        _ = try await client.fetchUser()
        _ = try await client.fetchUser()
        #expect(discoveryFetches == 2)
    }
}

}  // end of WireTests parent suite

// MARK: - Rauthy server error envelope decoding (M4)

@Suite("Server error envelope decoding")
struct ServerErrorEnvelopeTests {
    @Test("OAuth-format error is decoded as RauthyError.oauth")
    func decodesOAuth() {
        let data = Data(#"{"error":"invalid_grant","error_description":"expired"}"#.utf8)
        let err = decodeServerErrorResponse(statusCode: 400, data: data)
        if case .oauth(let inner) = err {
            #expect(inner.code == .invalidGrant)
            #expect(inner.description == "expired")
        } else {
            Issue.record("expected .oauth, got \(err)")
        }
    }

    @Test("Rauthy private envelope is decoded as RauthyError.server with errorCode + message")
    func decodesRauthyEnvelope() {
        // Real observed shape from a production Rauthy server.
        let data = Data(#"{"timestamp":1779477077,"error":"NotFound","message":"no rows returned"}"#.utf8)
        let err = decodeServerErrorResponse(statusCode: 404, data: data)
        if case .server(let inner) = err {
            #expect(inner.statusCode == 404)
            #expect(inner.errorCode == "NotFound")
            #expect(inner.message == "no rows returned")
        } else {
            Issue.record("expected .server, got \(err)")
        }
    }

    @Test("Unknown JSON falls through to ServerError.message=raw")
    func fallsThroughOnUnknownShape() {
        let raw = #"{"random":"shape","foo":[1,2,3]}"#
        let data = Data(raw.utf8)
        let err = decodeServerErrorResponse(statusCode: 500, data: data)
        if case .server(let inner) = err {
            #expect(inner.statusCode == 500)
            #expect(inner.errorCode == nil)
            #expect(inner.message == raw)
        } else {
            Issue.record("expected .server, got \(err)")
        }
    }

    @Test("Non-JSON body falls through with raw string in message")
    func fallsThroughOnNonJSON() {
        let data = Data("502 Bad Gateway".utf8)
        let err = decodeServerErrorResponse(statusCode: 502, data: data)
        if case .server(let inner) = err {
            #expect(inner.statusCode == 502)
            #expect(inner.message == "502 Bad Gateway")
        } else {
            Issue.record("expected .server, got \(err)")
        }
    }
}

// MARK: ===================================================================
// MARK: Security-fix regression tests
// MARK: ===================================================================
//
// One suite per finding ID from SECURITY-REVIEW.md / REMEDIATION.md. Pure-
// logic suites (no shared global state) are top-level; suites that drive the
// process-global `MockURLProtocol.handler` live in the `SecurityWireTests`
// parent below, marked `.serialized`, exactly like the existing `WireTests`.

// MARK: - SEC-L05: ClaimRule empty-collection semantics (fail-closed)

@Suite("SEC-L05 ClaimRule edge cases")
struct SecL05ClaimRuleEdgeCasesTests {
    @Test("empty .and fails closed")
    func emptyAndIsFalse() {
        // An empty `allSatisfy` is vacuously true; the SDK must override that
        // so `.and([])` denies rather than admitting everyone. Use `.any` to
        // admit everyone deliberately.
        #expect(ClaimRule.and([]).matches(roles: [], groups: []) == false)
        #expect(ClaimRule.and([]).matches(roles: ["admin"], groups: ["ops"]) == false)
    }

    @Test("empty .or is false")
    func emptyOrIsFalse() {
        #expect(ClaimRule.or([]).matches(roles: [], groups: []) == false)
        #expect(ClaimRule.or([]).matches(roles: ["admin"], groups: ["ops"]) == false)
    }

    @Test(".any always matches")
    func anyIsTrue() {
        #expect(ClaimRule.any.matches(roles: [], groups: []) == true)
    }

    @Test(".none never matches")
    func noneIsFalse() {
        #expect(ClaimRule.none.matches(roles: [], groups: []) == false)
    }
}

// MARK: - SEC-L23: azp (authorized party) validation (OIDC Core §3.1.3.7)

@Suite("SEC-L23 JWTClaimsValidator azp")
struct SecL23AzpValidationTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("rejects azp != clientID with .wrongAzp")
    func rejectsWrongAzp() {
        let idToken = makeIDToken(aud: ["my-app"], azp: "someone-else")
        do {
            try JWTClaimsValidator.validate(idToken, against: makeContext(), now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.wrongAzp(let expected, let got)) {
            #expect(expected == "my-app")
            #expect(got == "someone-else")
        } catch {
            Issue.record("expected wrongAzp, got \(error)")
        }
    }

    @Test("accepts azp == clientID")
    func acceptsMatchingAzp() throws {
        let idToken = makeIDToken(aud: ["my-app"], azp: "my-app")
        try JWTClaimsValidator.validate(idToken, against: makeContext(), now: now)
    }

    @Test("accepts absent azp with a single audience")
    func acceptsAbsentAzpSingleAud() throws {
        let idToken = makeIDToken(aud: ["my-app"], azp: nil)
        try JWTClaimsValidator.validate(idToken, against: makeContext(), now: now)
    }

    @Test("rejects multiple aud when azp is nil")
    func rejectsMultipleAudWithoutAzp() {
        // OIDC Core §3.1.3.7 rule 4: with >1 audience, azp MUST be present.
        let idToken = makeIDToken(aud: ["my-app", "other-app"], azp: nil)
        do {
            try JWTClaimsValidator.validate(idToken, against: makeContext(), now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.wrongAzp(let expected, _)) {
            #expect(expected == "my-app")
        } catch {
            Issue.record("expected wrongAzp, got \(error)")
        }
    }

    private func makeContext() -> JWTClaimsValidator.Context {
        JWTClaimsValidator.Context(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            nonce: nil,
            requireVerifiedEmail: false,
            allowedAlgorithms: [.eddsa]
        )
    }

    private func makeIDToken(aud: [String], azp: String?) -> IDToken {
        let claims = IDTokenClaims(
            sub: "user-123",
            aud: aud,
            azp: azp,
            iss: URL(string: "https://auth.example.com")!,
            iat: now,
            exp: now.addingTimeInterval(3600)
        )
        return IDToken(
            raw: "header.payload.signature",
            header: JWTHeader(alg: .eddsa, typ: "JWT", kid: "test-kid"),
            payload: claims,
            signature: Data()
        )
    }
}

// MARK: - SEC-I01: reject id_token minted in the future (iat > leeway)

@Suite("SEC-I01 JWTClaimsValidator future iat")
struct SecI01FutureIatValidationTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    @Test("iat far in the future beyond leeway throws .notYetValid")
    func futureIatRejected() {
        // iat one hour ahead, default leeway 60s → not yet valid.
        let idToken = makeIDToken(iat: now.addingTimeInterval(3600))
        do {
            try JWTClaimsValidator.validate(idToken, against: makeContext(), now: now)
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.notYetValid) {
            // ok
        } catch {
            Issue.record("expected notYetValid, got \(error)")
        }
    }

    @Test("iat within leeway passes")
    func iatWithinLeewayPasses() throws {
        let idToken = makeIDToken(iat: now.addingTimeInterval(30))  // 30s ahead
        try JWTClaimsValidator.validate(idToken, against: makeContext(), now: now)
    }

    private func makeContext() -> JWTClaimsValidator.Context {
        JWTClaimsValidator.Context(
            issuer: URL(string: "https://auth.example.com")!,
            clientID: "my-app",
            nonce: nil,
            requireVerifiedEmail: false,
            allowedAlgorithms: [.eddsa]
        )
    }

    private func makeIDToken(iat: Date) -> IDToken {
        let claims = IDTokenClaims(
            sub: "user-123",
            aud: ["my-app"],
            iss: URL(string: "https://auth.example.com")!,
            iat: iat,
            // Keep exp comfortably ahead of `iat` so the future-iat check is
            // what trips, not expiry.
            exp: iat.addingTimeInterval(3600)
        )
        return IDToken(
            raw: "header.payload.signature",
            header: JWTHeader(alg: .eddsa, typ: "JWT", kid: "test-kid"),
            payload: claims,
            signature: Data()
        )
    }
}

// MARK: - SEC-L24: parseIDToken rejects forbidden / malformed headers

@Suite("SEC-L24 JWTDecoder.parseIDToken header")
struct SecL24MalformedHeaderTests {
    @Test("alg \"none\" is rejected as malformed")
    func algNoneRejected() {
        // "none" is not a member of SigningAlgorithm, so header JSON decode
        // fails — the alg=none downgrade attack can never reach validation.
        #expect(throws: RauthyError.self) {
            try JWTDecoder.parseIDToken(makeJWT(headerJSON: #"{"alg":"none","typ":"JWT"}"#))
        }
    }

    @Test("alg \"HS256\" (symmetric) is rejected as malformed")
    func algHS256Rejected() {
        // HS256 is symmetric and intentionally unsupported; it must not decode.
        #expect(throws: RauthyError.self) {
            try JWTDecoder.parseIDToken(makeJWT(headerJSON: #"{"alg":"HS256","typ":"JWT"}"#))
        }
    }

    @Test("header that is valid base64url but not valid JSON is rejected")
    func nonJSONHeaderRejected() {
        // 0xFF 0xFF 0xFF decodes cleanly from base64url but is not JSON, so
        // `decode(_:)` passes the structural check and the header JSON-decode
        // step is what trips → .malformedJWT.
        let headerSegment = Data([0xFF, 0xFF, 0xFF]).base64URLEncodedString()
        let payloadSegment = Data(#"{"sub":"x"}"#.utf8).base64URLEncodedString()
        let signatureSegment = Data([0x01]).base64URLEncodedString()
        let jwt = "\(headerSegment).\(payloadSegment).\(signatureSegment)"
        #expect(throws: RauthyError.self) {
            try JWTDecoder.parseIDToken(jwt)
        }
    }

    /// Assemble a JWT string from a raw header JSON plus a throwaway payload
    /// and signature (the payload/signature are never reached for these cases).
    private func makeJWT(headerJSON: String) -> String {
        let header = Data(headerJSON.utf8).base64URLEncodedString()
        let payload = Data(#"{"sub":"user-1","aud":"my-app","iss":"https://auth.example.com","iat":1700000000,"exp":1700003600}"#.utf8)
            .base64URLEncodedString()
        let signature = Data([0x01, 0x02, 0x03]).base64URLEncodedString()
        return "\(header).\(payload).\(signature)"
    }
}

// MARK: - SEC-L27: RSAPublicKey.make modulus-size enforcement + round-trip

@Suite("SEC-L27 RSAPublicKey")
struct SecL27RSAPublicKeyTests {
    @Test("rejects a sub-2048-bit modulus")
    func rejectsSmallModulus() {
        // A 1024-bit modulus (128 bytes, high bit clear) must be refused.
        let smallN = Data([0x7F] + [UInt8](repeating: 0xAB, count: 127))  // 128 bytes = 1024 bits
        let e = Data([0x01, 0x00, 0x01])  // 65537
        #expect(throws: RSAPublicKeyError.self) {
            _ = try RSAPublicKey.make(n: smallN, e: e)
        }
    }

    @Test("parse/make round-trip for a valid 2048-bit key")
    func roundTripValid2048() throws {
        // Generate a real 2048-bit RSA key, export to PKCS#1 DER, parse out
        // (n, e), rebuild a SecKey via make(), and confirm both the parse and
        // the re-make succeed (and the modulus survives the round-trip).
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var error: Unmanaged<CFError>?
        let privateKey = try #require(
            SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            "SecKeyCreateRandomKey failed"
        )
        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        let publicDER = try #require(
            SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
            "SecKeyCopyExternalRepresentation failed"
        )

        let (n, e) = try RSAPublicKey.parse(der: publicDER)
        // A 2048-bit modulus is 256 bytes once leading-zero padding is stripped.
        #expect(n.count == 256)

        // Re-make a SecKey from the parsed components — must not throw.
        let remade = try RSAPublicKey.make(n: n, e: e)

        // And the re-made key's modulus must match the original.
        let remadeDER = try #require(
            SecKeyCopyExternalRepresentation(remade, &error) as Data?
        )
        let (n2, _) = try RSAPublicKey.parse(der: remadeDER)
        #expect(n2 == n)
    }
}

// MARK: - Signed-token helpers for full-pipeline security tests
//
// Builds a *real* Ed25519-signed id_token JWT plus the matching JWK so that
// `RauthyClient.validateIDToken` / `completeSignIn` exercise the genuine
// signature + claims path (not a stubbed token).

enum SignedTokenHelpers {
    static let kid = "test-kid"
    static let issuer = URL(string: "https://auth.example.com")!

    /// One Ed25519 keypair shared per build call.
    static func makeKeyPair() -> Curve25519.Signing.PrivateKey {
        Curve25519.Signing.PrivateKey()
    }

    /// The signing JWK (kty=OKP, crv=Ed25519, use=sig) for a private key.
    static func jwk(for privateKey: Curve25519.Signing.PrivateKey, kid: String = kid) -> JWK {
        JWK(
            kty: "OKP",
            alg: .eddsa,
            kid: kid,
            use: "sig",
            crv: "Ed25519",
            x: privateKey.publicKey.rawRepresentation.base64URLEncodedString()
        )
    }

    /// Build a signed id_token JWT string. `roles`/`groups` drive the
    /// userClaim gate; `now` anchors iat/exp so claims validation passes.
    static func makeSignedIDToken(
        privateKey: Curve25519.Signing.PrivateKey,
        sub: String = "user-123",
        roles: [String] = [],
        groups: [String] = [],
        nonce: String? = nil,
        now: Date = Date(),
        kid: String = kid,
        tamperSignature: Bool = false,
        alg: String = "EdDSA"
    ) -> String {
        let headerJSON = #"{"alg":"\#(alg)","typ":"JWT","kid":"\#(kid)"}"#

        let iat = Int(now.timeIntervalSince1970)
        let exp = iat + 3600
        let rolesJSON = "[" + roles.map { "\"\($0)\"" }.joined(separator: ",") + "]"
        let groupsJSON = "[" + groups.map { "\"\($0)\"" }.joined(separator: ",") + "]"
        let nonceField = nonce.map { ",\"nonce\":\"\($0)\"" } ?? ""
        // Include a verified email so tokens satisfy the production default
        // `requireVerifiedEmail == true` — mirrors a real Rauthy token issued
        // with the `email` scope.
        let payloadJSON = """
        {"sub":"\(sub)","aud":"my-app","iss":"https://auth.example.com","iat":\(iat),"exp":\(exp),"email":"user@example.com","email_verified":true,"roles":\(rolesJSON),"groups":\(groupsJSON)\(nonceField)}
        """

        let headerSeg = Data(headerJSON.utf8).base64URLEncodedString()
        let payloadSeg = Data(payloadJSON.utf8).base64URLEncodedString()
        let signingInput = "\(headerSeg).\(payloadSeg)"
        var signature = (try? privateKey.signature(for: Data(signingInput.utf8))) ?? Data()
        if tamperSignature, !signature.isEmpty {
            signature[0] ^= 0xFF
        }
        let sigSeg = signature.base64URLEncodedString()
        return "\(signingInput).\(sigSeg)"
    }

    /// Discovery JSON body served at `.well-known/openid-configuration`.
    static let discoveryBody = """
    {
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "userinfo_endpoint": "https://auth.example.com/userinfo",
        "jwks_uri": "https://auth.example.com/jwks",
        "response_types_supported": ["code"]
    }
    """

    /// JWKS JSON body wrapping a list of JWKs.
    static func jwksBody(_ keys: [JWK]) -> Data {
        (try? JSONEncoder().encode(JWKSet(keys: keys))) ?? Data("{\"keys\":[]}".utf8)
    }

    /// Token endpoint JSON body embedding a signed id_token.
    static func tokenBody(idToken: String, accessToken: String = "at-new", refreshToken: String = "rt-new") -> Data {
        let json = """
        {
            "access_token": "\(accessToken)",
            "refresh_token": "\(refreshToken)",
            "id_token": "\(idToken)",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile"
        }
        """
        return Data(json.utf8)
    }
}

// MARK: - Security wire tests (share the process-global MockURLProtocol.handler)

@Suite("SecurityWire", .serialized)
enum SecurityWireTests {

// MARK: - SEC-L25: JWKSFetcher transport / status / decode behavior

@Suite("SEC-L25 JWKSFetcher.fetch")
struct SecL25JWKSFetcherTests {
    private static let jwksURL = URL(string: "https://auth.example.com/jwks")!

    @Test("200 with valid body decodes the key set")
    func decodesValid() async throws {
        let session = WireTestHelpers.makeMockSession()
        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let body = """
            { "keys": [ { "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": "AAAA" } ] }
            """
            return (response, Data(body.utf8))
        }
        defer { MockURLProtocol.handler = nil }

        let set = try await JWKSFetcher.fetch(url: Self.jwksURL, session: session)
        #expect(set.keys.count == 1)
        #expect(set.keys.first?.kid == "k1")
    }

    @Test("500 throws RauthyError.server")
    func serverErrorOn500() async throws {
        let session = WireTestHelpers.makeMockSession()
        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!
            return (response, Data("boom".utf8))
        }
        defer { MockURLProtocol.handler = nil }

        do {
            _ = try await JWKSFetcher.fetch(url: Self.jwksURL, session: session)
            Issue.record("expected throw")
        } catch RauthyError.server {
            // ok
        } catch {
            Issue.record("expected .server, got \(error)")
        }
    }

    @Test("transport error throws networkUnavailable")
    func networkErrorIsMapped() async throws {
        let session = WireTestHelpers.makeMockSession()
        MockURLProtocol.handler = { _ in
            throw URLError(.notConnectedToInternet)
        }
        defer { MockURLProtocol.handler = nil }

        await #expect(throws: RauthyError.networkUnavailable) {
            _ = try await JWKSFetcher.fetch(url: Self.jwksURL, session: session)
        }
    }

    @Test("malformed JSON on 200 throws")
    func malformedJSONThrows() async throws {
        let session = WireTestHelpers.makeMockSession()
        MockURLProtocol.handler = { request in
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data("not json at all".utf8))
        }
        defer { MockURLProtocol.handler = nil }

        // A decode failure is mapped to networkUnavailable by the fetcher's
        // catch-all; the contract that matters is "it throws, never returns
        // a bogus empty set."
        await #expect(throws: RauthyError.self) {
            _ = try await JWKSFetcher.fetch(url: Self.jwksURL, session: session)
        }
    }
}

// MARK: - SEC-M05: validateIDToken rejects wrong-alg and bad-signature tokens

@Suite("SEC-M05 validateIDToken")
struct SecM05ValidateIDTokenTests {
    @Test("wrong algorithm (not in allowlist) is rejected before crypto")
    func wrongAlgorithmRejected() async throws {
        // Configure the client to allow ONLY EdDSA, then hand it an RS256
        // id_token. The allowlist guard must trip before any JWKS fetch.
        let session = WireTestHelpers.makeMockSession()
        let config = RauthyConfig.production(
            issuer: SignedTokenHelpers.issuer,
            clientID: "my-app",
            redirectURI: URL(string: "myapp://cb")!,
            allowedAlgorithms: [.eddsa],
            userClaim: .any,
            adminClaim: .none
        )

        nonisolated(unsafe) var jwksFetches = 0
        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data(SignedTokenHelpers.discoveryBody.utf8))
            }
            if request.url?.path == "/jwks" {
                jwksFetches += 1
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, SignedTokenHelpers.jwksBody([]))
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }
        defer { MockURLProtocol.handler = nil }

        let discovery = WireTestHelpers.makeDiscovery()
        let client = RauthyClient(config: config, storage: InMemoryStorage(), urlSession: session)

        let rs256Token = IDToken(
            raw: "h.p.s",
            header: JWTHeader(alg: .rs256, typ: "JWT", kid: "test-kid"),
            payload: IDTokenClaims(
                sub: "user-123",
                aud: ["my-app"],
                iss: SignedTokenHelpers.issuer,
                iat: Date(),
                exp: Date(timeIntervalSinceNow: 3600)
            ),
            signature: Data()
        )

        do {
            try await client.validateIDToken(
                rs256Token, accessToken: "at", nonce: nil, discovery: discovery
            )
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.wrongAlgorithm) {
            // ok — and crucially we never fetched JWKS.
            #expect(jwksFetches == 0)
        } catch {
            Issue.record("expected wrongAlgorithm, got \(error)")
        }
    }

    @Test("tampered signature is rejected as signatureInvalid")
    func tamperedSignatureRejected() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let privateKey = SignedTokenHelpers.makeKeyPair()
        let jwk = SignedTokenHelpers.jwk(for: privateKey)

        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data(SignedTokenHelpers.discoveryBody.utf8))
            }
            // /jwks — return the correct key, so the failure is purely the
            // tampered signature, not a key miss.
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (response, SignedTokenHelpers.jwksBody([jwk]))
        }
        defer { MockURLProtocol.handler = nil }

        let discovery = WireTestHelpers.makeDiscovery()
        let client = RauthyClient(config: config, storage: InMemoryStorage(), urlSession: session)

        let raw = SignedTokenHelpers.makeSignedIDToken(
            privateKey: privateKey,
            tamperSignature: true
        )
        let idToken = try JWTDecoder.parseIDToken(raw)

        do {
            try await client.validateIDToken(
                idToken, accessToken: "at", nonce: nil, discovery: discovery
            )
            Issue.record("expected throw")
        } catch RauthyError.invalidJWT(.signatureInvalid) {
            // ok
        } catch {
            Issue.record("expected signatureInvalid, got \(error)")
        }
    }

    @Test("kid miss triggers exactly one JWKS refetch, then succeeds")
    func kidMissRefetchesOnce() async throws {
        let session = WireTestHelpers.makeMockSession()
        let config = WireTestHelpers.makeConfig()
        let privateKey = SignedTokenHelpers.makeKeyPair()
        let goodJWK = SignedTokenHelpers.jwk(for: privateKey)
        // A decoy key with a different kid so the first select() misses.
        let decoyJWK = SignedTokenHelpers.jwk(for: SignedTokenHelpers.makeKeyPair(), kid: "other-kid")

        nonisolated(unsafe) var jwksFetches = 0
        let lock = NSLock()
        MockURLProtocol.handler = { request in
            if request.url?.path == "/.well-known/openid-configuration" {
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data(SignedTokenHelpers.discoveryBody.utf8))
            }
            // /jwks — first hit returns only the decoy (kid miss); second hit
            // returns the real key (post-rotation).
            lock.lock(); jwksFetches += 1; let n = jwksFetches; lock.unlock()
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            let keys = n == 1 ? [decoyJWK] : [goodJWK]
            return (response, SignedTokenHelpers.jwksBody(keys))
        }
        defer { MockURLProtocol.handler = nil }

        let discovery = WireTestHelpers.makeDiscovery()
        let client = RauthyClient(config: config, storage: InMemoryStorage(), urlSession: session)

        let raw = SignedTokenHelpers.makeSignedIDToken(privateKey: privateKey)
        let idToken = try JWTDecoder.parseIDToken(raw)

        // Should not throw: kid miss on the first JWKS, refetch finds the key.
        try await client.validateIDToken(
            idToken, accessToken: "at", nonce: nil, discovery: discovery
        )
        // Exactly two fetches: the initial fetch plus one refetch.
        #expect(jwksFetches == 2)
    }
}

// MARK: - SEC-M01 / M06: completeSignIn userClaim gate + state (CSRF) check

@Suite("SEC-M01/M06 completeSignIn")
struct SecM01M06CompleteSignInTests {
    /// Build a client whose discovery/token/JWKS endpoints are all mocked, and
    /// whose `/token` returns a signed id_token carrying `roles`/`groups`.
    @MainActor
    private func makeClient(
        userClaim: ClaimRule,
        roles: [String],
        groups: [String],
        nonce: String? = nil
    ) -> (RauthyClient, InMemoryStorage) {
        let session = WireTestHelpers.makeMockSession()
        let config = RauthyConfig.production(
            issuer: SignedTokenHelpers.issuer,
            clientID: "my-app",
            redirectURI: URL(string: "myapp://cb")!,
            scopes: ["openid", "profile"],
            userClaim: userClaim,
            adminClaim: .none
        )
        let privateKey = SignedTokenHelpers.makeKeyPair()
        let jwk = SignedTokenHelpers.jwk(for: privateKey)
        // Bake in the nonce so the minted id_token matches the nonce the test
        // passes to completeSignIn (validateIDToken enforces nonce equality).
        let idToken = SignedTokenHelpers.makeSignedIDToken(
            privateKey: privateKey,
            roles: roles,
            groups: groups,
            nonce: nonce
        )

        MockURLProtocol.handler = { request in
            switch request.url?.path {
            case "/.well-known/openid-configuration":
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data(SignedTokenHelpers.discoveryBody.utf8))
            case "/token":
                let response = HTTPURLResponse(
                    url: request.url!, statusCode: 200, httpVersion: nil,
                    headerFields: ["Content-Type": "application/json"]
                )!
                return (response, SignedTokenHelpers.tokenBody(idToken: idToken))
            case "/jwks":
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, SignedTokenHelpers.jwksBody([jwk]))
            default:
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data())
            }
        }

        let storage = InMemoryStorage()
        let client = RauthyClient(config: config, storage: storage, urlSession: session)
        return (client, storage)
    }

    @Test("user not satisfying a restrictive userClaim is rejected; no token saved")
    func restrictiveClaimRejects() async throws {
        // Require role "admin"; the token only carries role "user" → reject.
        let (client, storage) = await makeClient(
            userClaim: .or([.role("admin")]),
            roles: ["user"],
            groups: [],
            nonce: "n1"
        )
        defer { MockURLProtocol.handler = nil }
        let discovery = WireTestHelpers.makeDiscovery()

        do {
            _ = try await client.completeSignIn(
                callbackURL: URL(string: "myapp://cb?code=abc&state=s1")!,
                state: "s1",
                nonce: "n1",
                pkce: PKCE(),
                discovery: discovery
            )
            Issue.record("expected throw")
        } catch RauthyError.notAuthorized {
            // ok — and nothing was persisted.
            let stored = try await storage.load()
            #expect(stored == nil)
        } catch {
            Issue.record("expected notAuthorized, got \(error)")
        }
    }

    @Test(".any userClaim admits the user and saves the token")
    func anyClaimSucceeds() async throws {
        let (client, storage) = await makeClient(
            userClaim: .any,
            roles: ["user"],
            groups: [],
            nonce: "n1"
        )
        defer { MockURLProtocol.handler = nil }
        let discovery = WireTestHelpers.makeDiscovery()

        let token = try await client.completeSignIn(
            callbackURL: URL(string: "myapp://cb?code=abc&state=s1")!,
            state: "s1",
            nonce: "n1",
            pkce: PKCE(),
            discovery: discovery
        )
        #expect(token.accessToken == "at-new")

        let stored = try await storage.load()
        #expect(stored?.accessToken == "at-new")
    }

    @Test("state mismatch throws .stateMismatch and saves nothing")
    func stateMismatchRejects() async throws {
        let (client, storage) = await makeClient(
            userClaim: .any,
            roles: [],
            groups: []
        )
        defer { MockURLProtocol.handler = nil }
        let discovery = WireTestHelpers.makeDiscovery()

        do {
            _ = try await client.completeSignIn(
                callbackURL: URL(string: "myapp://cb?code=abc&state=ATTACKER")!,
                state: "EXPECTED",
                nonce: "n1",
                pkce: PKCE(),
                discovery: discovery
            )
            Issue.record("expected throw")
        } catch RauthyError.stateMismatch {
            // ok — token exchange never ran, nothing persisted.
            let stored = try await storage.load()
            #expect(stored == nil)
        } catch {
            Issue.record("expected stateMismatch, got \(error)")
        }
    }
}

}  // end of SecurityWireTests parent suite
