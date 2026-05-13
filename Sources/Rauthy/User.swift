import Foundation

/// A snapshot of the currently-signed-in user.
///
/// Can be constructed two ways:
///   - From a verified `IDToken` (synchronous, no network)
///   - From a `/userinfo` endpoint response (after a network call)
///
/// Both paths produce the same shape. The `/userinfo` path may include claims
/// not in the ID token (e.g., `mfaEnabled`) and reflects the latest
/// server-side state.
public struct User: Sendable, Codable, Equatable {
    /// Rauthy's internal user UUID. From the `id` field on `/userinfo` responses,
    /// or falls back to `sub` when only an ID token is available.
    public let id: String

    /// The OIDC `sub` claim. Stable across the user's lifetime at this issuer.
    public let subject: String

    /// Email address. May be `nil` if the `email` scope was not granted.
    public let email: String?

    /// Whether the email has been verified by the user. `nil` if email is absent.
    public let emailVerified: Bool?

    public let preferredUsername: String?
    public let givenName: String?
    public let familyName: String?
    public let pictureURL: URL?
    public let locale: String?
    public let address: AddressClaim?
    public let phoneNumber: String?
    public let phoneNumberVerified: Bool?
    public let birthdate: String?

    /// Roles assigned to this user, from the `roles` scope.
    public let roles: [String]

    /// Groups this user belongs to, from the `groups` scope.
    public let groups: [String]

    /// Whether MFA is enabled on this account. Only populated from `/userinfo`;
    /// `nil` when constructed from an ID token alone.
    public let mfaEnabled: Bool?

    /// WebID URL, if Rauthy is configured to issue WebIDs.
    public let webID: URL?

    /// Any custom claims defined per-client in Rauthy's admin UI.
    public let custom: [String: JSONValue]

    public init(
        id: String,
        subject: String,
        email: String? = nil,
        emailVerified: Bool? = nil,
        preferredUsername: String? = nil,
        givenName: String? = nil,
        familyName: String? = nil,
        pictureURL: URL? = nil,
        locale: String? = nil,
        address: AddressClaim? = nil,
        phoneNumber: String? = nil,
        phoneNumberVerified: Bool? = nil,
        birthdate: String? = nil,
        roles: [String] = [],
        groups: [String] = [],
        mfaEnabled: Bool? = nil,
        webID: URL? = nil,
        custom: [String: JSONValue] = [:]
    ) {
        self.id = id
        self.subject = subject
        self.email = email
        self.emailVerified = emailVerified
        self.preferredUsername = preferredUsername
        self.givenName = givenName
        self.familyName = familyName
        self.pictureURL = pictureURL
        self.locale = locale
        self.address = address
        self.phoneNumber = phoneNumber
        self.phoneNumberVerified = phoneNumberVerified
        self.birthdate = birthdate
        self.roles = roles
        self.groups = groups
        self.mfaEnabled = mfaEnabled
        self.webID = webID
        self.custom = custom
    }

    /// Construct a User from a verified ID Token. Synchronous, no network call.
    ///
    /// Use this immediately after sign-in to populate a snapshot of who the
    /// user is. For fresher data (and additional Rauthy-specific fields like
    /// `mfaEnabled`), call the /userinfo endpoint separately.
    public init(idToken: IDToken) {
        let claims = idToken.payload
        // ID tokens don't carry a separate `uid` claim; use sub as id.
        self.init(
            id: claims.sub,
            subject: claims.sub,
            email: claims.email,
            emailVerified: claims.emailVerified,
            preferredUsername: claims.preferredUsername,
            givenName: claims.givenName,
            familyName: claims.familyName,
            pictureURL: claims.picture,
            locale: claims.locale,
            address: claims.address,
            phoneNumber: claims.phoneNumber,
            phoneNumberVerified: claims.phoneNumberVerified,
            birthdate: claims.birthdate,
            roles: claims.roles,
            groups: claims.groups,
            mfaEnabled: nil,
            webID: claims.webID,
            custom: claims.custom
        )
    }

    /// Construct a User from a raw `/userinfo` response body.
    ///
    /// Rauthy's userinfo endpoint returns a richer payload than the ID token
    /// (includes `mfaEnabled` and the Rauthy internal `id` distinct from `sub`).
    public init(userInfoResponse data: Data) throws {
        let decoder = JSONDecoder()
        let body = try decoder.decode(UserInfoResponse.self, from: data)
        self.init(
            id: body.id,
            subject: body.sub,
            email: body.email,
            emailVerified: body.emailVerified,
            preferredUsername: body.preferredUsername,
            givenName: body.givenName,
            familyName: body.familyName,
            pictureURL: body.picture,
            locale: body.locale,
            address: body.address,
            phoneNumber: body.phone,
            phoneNumberVerified: nil,
            birthdate: body.birthdate,
            roles: body.roles,
            groups: body.groups ?? [],
            mfaEnabled: body.mfaEnabled,
            webID: body.webID,
            custom: [:]
        )
    }
}

/// Internal: shape of Rauthy's `/userinfo` endpoint response.
private struct UserInfoResponse: Codable {
    let id: String
    let sub: String
    let email: String?
    let emailVerified: Bool?
    let preferredUsername: String?
    let givenName: String?
    let familyName: String?
    let picture: URL?
    let locale: String?
    let address: AddressClaim?
    let phone: String?
    let birthdate: String?
    let roles: [String]
    let groups: [String]?
    let mfaEnabled: Bool?
    let webID: URL?

    private enum CodingKeys: String, CodingKey {
        case id, sub, email
        case emailVerified = "email_verified"
        case preferredUsername = "preferred_username"
        case givenName = "given_name"
        case familyName = "family_name"
        case picture, locale, address, phone, birthdate, roles, groups
        case mfaEnabled = "mfa_enabled"
        case webID = "webid"
    }
}
