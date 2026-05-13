import Foundation

/// Standard OIDC claims plus Rauthy-specific extensions, as encoded inside the
/// payload (second segment) of an ID Token.
///
/// Mirrors `JwtIdClaims` in the Rauthy server's Rust client (`src/token_set.rs`).
public struct IDTokenClaims: Sendable, Codable, Equatable {
    // MARK: OIDC standard claims

    /// Subject — Rauthy's user UUID (or a stable per-client pairwise ID).
    public let sub: String

    /// Audience — typically a single client ID, sometimes an array.
    public let aud: [String]

    /// Authorized party — must match the SDK's configured `clientID`.
    public let azp: String?

    /// Issuer URL — must match the SDK's configured Rauthy issuer.
    public let iss: URL

    /// Issued-at time.
    public let iat: Date

    /// Expiration time.
    public let exp: Date

    /// Nonce — must match the nonce sent in the authorization request
    /// (validated at sign-in time).
    public let nonce: String?

    /// Authentication Methods Reference. Common values: `"pwd"`, `"mfa"`.
    public let amr: [String]

    /// When the user actually authenticated (vs. when this token was minted).
    public let authTime: Date?

    /// Hash of the associated access token, used for additional binding.
    public let atHash: String?

    /// Session ID — useful for backchannel logout correlation.
    public let sid: String?

    // MARK: User profile claims

    public let email: String?
    public let emailVerified: Bool?
    public let preferredUsername: String?
    public let givenName: String?
    public let familyName: String?
    public let picture: URL?
    public let locale: String?
    public let address: AddressClaim?
    public let phoneNumber: String?
    public let phoneNumberVerified: Bool?
    public let birthdate: String?
    public let zoneinfo: String?

    // MARK: Rauthy-specific extensions

    /// Roles assigned to this user, from the `roles` scope.
    public let roles: [String]

    /// Groups this user belongs to, from the `groups` scope.
    public let groups: [String]

    /// WebID URL, if Rauthy is configured to issue WebIDs.
    public let webID: URL?

    /// Any custom claims defined per-client in Rauthy's admin UI.
    public let custom: [String: JSONValue]

    public init(
        sub: String,
        aud: [String],
        azp: String? = nil,
        iss: URL,
        iat: Date,
        exp: Date,
        nonce: String? = nil,
        amr: [String] = [],
        authTime: Date? = nil,
        atHash: String? = nil,
        sid: String? = nil,
        email: String? = nil,
        emailVerified: Bool? = nil,
        preferredUsername: String? = nil,
        givenName: String? = nil,
        familyName: String? = nil,
        picture: URL? = nil,
        locale: String? = nil,
        address: AddressClaim? = nil,
        phoneNumber: String? = nil,
        phoneNumberVerified: Bool? = nil,
        birthdate: String? = nil,
        zoneinfo: String? = nil,
        roles: [String] = [],
        groups: [String] = [],
        webID: URL? = nil,
        custom: [String: JSONValue] = [:]
    ) {
        self.sub = sub
        self.aud = aud
        self.azp = azp
        self.iss = iss
        self.iat = iat
        self.exp = exp
        self.nonce = nonce
        self.amr = amr
        self.authTime = authTime
        self.atHash = atHash
        self.sid = sid
        self.email = email
        self.emailVerified = emailVerified
        self.preferredUsername = preferredUsername
        self.givenName = givenName
        self.familyName = familyName
        self.picture = picture
        self.locale = locale
        self.address = address
        self.phoneNumber = phoneNumber
        self.phoneNumberVerified = phoneNumberVerified
        self.birthdate = birthdate
        self.zoneinfo = zoneinfo
        self.roles = roles
        self.groups = groups
        self.webID = webID
        self.custom = custom
    }

    private enum CodingKeys: String, CodingKey {
        case sub, aud, azp, iss, iat, exp, nonce, amr, sid
        case authTime = "auth_time"
        case atHash = "at_hash"
        case email
        case emailVerified = "email_verified"
        case preferredUsername = "preferred_username"
        case givenName = "given_name"
        case familyName = "family_name"
        case picture, locale, address
        case phoneNumber = "phone_number"
        case phoneNumberVerified = "phone_number_verified"
        case birthdate, zoneinfo, roles, groups
        case webID = "webid"
        case custom
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sub = try container.decode(String.self, forKey: .sub)
        aud = try Self.decodeStringOrArray(container, key: .aud)
        azp = try container.decodeIfPresent(String.self, forKey: .azp)
        iss = try container.decode(URL.self, forKey: .iss)
        iat = try container.decode(Date.self, forKey: .iat)
        exp = try container.decode(Date.self, forKey: .exp)
        nonce = try container.decodeIfPresent(String.self, forKey: .nonce)
        amr = (try? Self.decodeStringOrArray(container, key: .amr)) ?? []
        authTime = try container.decodeIfPresent(Date.self, forKey: .authTime)
        atHash = try container.decodeIfPresent(String.self, forKey: .atHash)
        sid = try container.decodeIfPresent(String.self, forKey: .sid)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        emailVerified = try container.decodeIfPresent(Bool.self, forKey: .emailVerified)
        preferredUsername = try container.decodeIfPresent(String.self, forKey: .preferredUsername)
        givenName = try container.decodeIfPresent(String.self, forKey: .givenName)
        familyName = try container.decodeIfPresent(String.self, forKey: .familyName)
        picture = try container.decodeIfPresent(URL.self, forKey: .picture)
        locale = try container.decodeIfPresent(String.self, forKey: .locale)
        address = try container.decodeIfPresent(AddressClaim.self, forKey: .address)
        phoneNumber = try container.decodeIfPresent(String.self, forKey: .phoneNumber)
        phoneNumberVerified = try container.decodeIfPresent(Bool.self, forKey: .phoneNumberVerified)
        birthdate = try container.decodeIfPresent(String.self, forKey: .birthdate)
        zoneinfo = try container.decodeIfPresent(String.self, forKey: .zoneinfo)
        roles = (try? container.decodeIfPresent([String].self, forKey: .roles)) ?? []
        groups = (try? container.decodeIfPresent([String].self, forKey: .groups)) ?? []
        webID = try container.decodeIfPresent(URL.self, forKey: .webID)
        custom = (try? container.decodeIfPresent([String: JSONValue].self, forKey: .custom)) ?? [:]
    }

    /// OIDC permits `aud` and `amr` to be either a single string or an array.
    private static func decodeStringOrArray(
        _ container: KeyedDecodingContainer<CodingKeys>,
        key: CodingKeys
    ) throws -> [String] {
        if let array = try? container.decode([String].self, forKey: key) {
            return array
        }
        if let single = try? container.decode(String.self, forKey: key) {
            return [single]
        }
        throw DecodingError.typeMismatch(
            [String].self,
            DecodingError.Context(
                codingPath: container.codingPath + [key],
                debugDescription: "Expected String or [String] for \(key)"
            )
        )
    }
}

/// OIDC `address` claim, when issued under the `address` scope.
public struct AddressClaim: Sendable, Codable, Equatable, Hashable {
    public let formatted: String?
    public let streetAddress: String?
    public let locality: String?
    public let region: String?
    public let postalCode: String?
    public let country: String?

    public init(
        formatted: String? = nil,
        streetAddress: String? = nil,
        locality: String? = nil,
        region: String? = nil,
        postalCode: String? = nil,
        country: String? = nil
    ) {
        self.formatted = formatted
        self.streetAddress = streetAddress
        self.locality = locality
        self.region = region
        self.postalCode = postalCode
        self.country = country
    }

    private enum CodingKeys: String, CodingKey {
        case formatted
        case streetAddress = "street_address"
        case locality, region
        case postalCode = "postal_code"
        case country
    }
}
