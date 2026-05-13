import Foundation

/// Rauthy account self-service API. Access via `client.account`.
///
/// All methods authenticate as the currently-signed-in user. The `id` in
/// Rauthy's `/users/{id}` URLs is sourced from the local ID token's `sub`
/// claim — this assumes the default Rauthy config where `sub == uid`.
public struct AccountAPI: Sendable {
    let client: RauthyClient

    public init(client: RauthyClient) {
        self.client = client
    }

    // MARK: - Profile updates

    /// Update one or more profile fields. All parameters are optional;
    /// only the non-nil ones are sent to the server.
    ///
    /// Email changes trigger a verification email — the new email isn't
    /// active until the user clicks the link Rauthy sends.
    ///
    /// Password changes require `passwordCurrent` (and `mfaCode` if MFA
    /// is enabled). On success, existing refresh tokens are NOT invalidated
    /// — the user stays signed in.
    public func updateProfile(
        email: String? = nil,
        givenName: String? = nil,
        familyName: String? = nil,
        language: String? = nil,
        passwordCurrent: String? = nil,
        passwordNew: String? = nil,
        mfaCode: String? = nil
    ) async throws {
        try await client.performUpdateUserSelf(
            email: email,
            givenName: givenName,
            familyName: familyName,
            language: language,
            passwordCurrent: passwordCurrent,
            passwordNew: passwordNew,
            mfaCode: mfaCode
        )
    }

    /// Update the preferred username (also known as the "display username").
    /// Subject to Rauthy's username regex (alphanumeric + a small set of
    /// punctuation, 1-32 chars).
    public func updatePreferredUsername(_ newValue: String) async throws {
        try await client.performUpdatePreferredUsername(newValue)
    }

    // MARK: - Devices

    /// List devices with active Rauthy sessions for the current user.
    public func devices() async throws -> [Device] {
        try await client.performListDevices()
    }

    /// Revoke a device's session.
    public func revokeDevice(_ device: Device) async throws {
        try await client.performRevokeDevice(deviceID: device.id, name: nil)
    }

    /// Revoke a device by its ID without first fetching the list.
    public func revokeDevice(id: String) async throws {
        try await client.performRevokeDevice(deviceID: id, name: nil)
    }

    // MARK: - Account deletion

    /// Check whether self-deletion is enabled for this user.
    /// Throws `RauthyError.server(...)` with 4xx status if disabled.
    public func requestAccountDeletion() async throws {
        try await client.performRequestAccountDeletion()
    }

    /// Permanently delete the current user account. Make sure the user has
    /// confirmed this in your UI — there's no undo. Locally also clears
    /// stored tokens on success.
    public func confirmAccountDeletion() async throws {
        try await client.performConfirmAccountDeletion()
    }
}

// MARK: - Internal request bodies (mirror Rauthy's api_types)

internal struct UpdateUserSelfBody: Codable {
    var email: String?
    var givenName: String?
    var familyName: String?
    var language: String?
    var passwordCurrent: String?
    var passwordNew: String?
    var mfaCode: String?

    private enum CodingKeys: String, CodingKey {
        case email
        case givenName = "given_name"
        case familyName = "family_name"
        case language
        case passwordCurrent = "password_current"
        case passwordNew = "password_new"
        case mfaCode = "mfa_code"
    }

    /// Whether any field is set (so we can avoid POSTing an empty body).
    var isEmpty: Bool {
        email == nil && givenName == nil && familyName == nil
            && language == nil && passwordCurrent == nil
            && passwordNew == nil && mfaCode == nil
    }
}

internal struct PreferredUsernameBody: Codable {
    let preferredUsername: String

    private enum CodingKeys: String, CodingKey {
        case preferredUsername = "preferred_username"
    }
}

internal struct DeviceRequestBody: Codable {
    let deviceID: String
    let name: String?

    private enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case name
    }
}
