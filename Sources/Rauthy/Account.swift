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

    /// Rename a device. Subject to Rauthy's name regex (2-128 chars,
    /// alphanumeric + a small punctuation set).
    public func renameDevice(_ device: Device, to newName: String) async throws {
        try await client.performRenameDevice(deviceID: device.id, newName: newName)
    }

    /// Rename a device by ID.
    public func renameDevice(id: String, to newName: String) async throws {
        try await client.performRenameDevice(deviceID: id, newName: newName)
    }

    // MARK: - Avatar

    /// Upload a new avatar image. Replaces any existing avatar.
    ///
    /// Rauthy auto-converts to WebP and resizes to its configured max
    /// dimension (default 192x192). Acceptable inputs include JPEG, PNG,
    /// WebP, and SVG (SVG gets sanitized server-side).
    ///
    /// - Parameters:
    ///   - imageData: Raw image bytes.
    ///   - mimeType: Required. Common values: `"image/jpeg"`, `"image/png"`,
    ///     `"image/webp"`, `"image/svg+xml"`.
    /// - Returns: The new picture ID, which you can compose into the
    ///   picture-download URL via ``pictureURL(pictureID:mimeType:)``.
    @discardableResult
    public func uploadAvatar(_ imageData: Data, mimeType: String) async throws -> String {
        try await client.performUploadAvatar(imageData: imageData, mimeType: mimeType)
    }

    /// Delete an avatar by its picture ID.
    public func deleteAvatar(pictureID: String) async throws {
        try await client.performDeleteAvatar(pictureID: pictureID)
    }

    /// Build the URL for downloading an avatar. Use with `AsyncImage` or
    /// `URLSession` — the image is publicly fetchable (no auth header needed).
    public func pictureURL(userID: String, pictureID: String) -> URL {
        client.pictureURL(userID: userID, pictureID: pictureID)
    }

    // MARK: - Passkey conversion

    /// Convert the account to passkey-only authentication. After this,
    /// the user can no longer sign in with their password — only with a
    /// registered passkey. **Requires at least one passkey to already be
    /// registered** (use ``PasskeyAPI/register(named:anchor:)`` first).
    ///
    /// One-way operation: once converted, the password is stripped from
    /// the database. Rauthy may offer a "revert" path through the account
    /// dashboard, but the SDK doesn't expose it.
    public func convertToPasskeyOnly() async throws {
        try await client.performConvertToPasskeyOnly()
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
