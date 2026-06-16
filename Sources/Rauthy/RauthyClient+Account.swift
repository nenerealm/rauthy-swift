import Foundation

/// Account-API implementations live as an extension on `RauthyClient` so
/// they can reach the actor's private state (storage, URLSession, current
/// user ID derived from the cached ID token). The public façade is
/// `AccountAPI`, accessed via `client.account`.
public extension RauthyClient {
    /// Namespace for self-service account operations.
    var account: AccountAPI {
        AccountAPI(client: self)
    }
}

extension RauthyClient {
    // MARK: - User ID resolution

    /// Resolve the current user's Rauthy ID from the locally-stored ID token.
    /// Assumes the default Rauthy config where `sub == uid`.
    internal func currentUserID() async throws -> String {
        guard let token = try await loadStoredToken(),
              let idToken = token.idToken else {
            throw RauthyError.reauthenticationRequired
        }
        return idToken.payload.sub
    }

    internal func loadStoredToken() async throws -> Token? {
        try await storage.load()
    }

    /// Build the public URL for downloading an avatar. Synchronous —
    /// doesn't need an access token because picture downloads are public.
    /// Use with `AsyncImage` or `URLSession`.
    public nonisolated func pictureURL(userID: String, pictureID: String) -> URL {
        let baseString = config.issuer.absoluteString
        let trimmedBase = baseString.hasSuffix("/")
            ? String(baseString.dropLast())
            : baseString
        let safeUser = userID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)
            ?? userID
        let safePicture = pictureID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)
            ?? pictureID
        // swift-format-ignore: NeverForceUnwrap
        return URL(string: "\(trimmedBase)/users/\(safeUser)/picture/\(safePicture)")!
    }

    /// Convenience: produce an authenticated GET/POST/PUT/DELETE URLRequest
    /// targeting one of Rauthy's `/users/{id}/...` endpoints.
    internal func authenticatedRequest(
        method: String,
        relativePath: String,
        body: Data? = nil,
        contentType: String? = nil
    ) async throws -> URLRequest {
        let accessToken = try await validAccessToken()
        let userID = try await currentUserID()
        let trimmed = relativePath.replacingOccurrences(of: "{id}", with: userID)
        let url = appendPath(to: config.issuer, path: trimmed)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        if body != nil {
            request.setValue(contentType ?? "application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    private func appendPath(to base: URL, path: String) -> URL {
        // Avoid URL.appendingPathComponent's percent-encoding of '/' inside the path.
        let baseString = base.absoluteString
        let trimmedBase = baseString.hasSuffix("/") ? String(baseString.dropLast()) : baseString
        let trimmedPath = path.hasPrefix("/") ? String(path.dropFirst()) : path
        // swift-format-ignore: NeverForceUnwrap
        return URL(string: "\(trimmedBase)/\(trimmedPath)")!
    }

    /// Execute an authenticated request and return raw `(Data, HTTPURLResponse)`.
    /// Handles common error mappings: 401 → reauthenticationRequired, 4xx/5xx → server error.
    internal func executeAuthenticated(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw RauthyError.networkUnavailable
        }
        guard let http = response as? HTTPURLResponse else {
            throw RauthyError.networkUnavailable
        }
        if http.statusCode == 401 {
            throw RauthyError.reauthenticationRequired
        }
        if http.statusCode >= 400 {
            throw decodeServerErrorResponse(statusCode: http.statusCode, data: data)
        }
        return (data, http)
    }

    // MARK: - Profile

    internal func performUpdateUserSelf(
        email: String?,
        givenName: String?,
        familyName: String?,
        language: String?,
        passwordCurrent: String?,
        passwordNew: String?,
        mfaCode: String?
    ) async throws {
        var body = UpdateUserSelfBody()
        body.email = email
        body.givenName = givenName
        body.familyName = familyName
        body.language = language
        body.passwordCurrent = passwordCurrent
        body.passwordNew = passwordNew
        body.mfaCode = mfaCode

        if body.isEmpty {
            return  // Nothing to update, treat as no-op.
        }

        let data = try JSONEncoder().encode(body)
        let request = try await authenticatedRequest(
            method: "PUT",
            relativePath: "users/{id}/self",
            body: data
        )
        _ = try await executeAuthenticated(request)
    }

    internal func performUpdatePreferredUsername(_ value: String) async throws {
        let body = try JSONEncoder().encode(PreferredUsernameBody(preferredUsername: value))
        let request = try await authenticatedRequest(
            method: "PUT",
            relativePath: "users/{id}/self/preferred_username",
            body: body
        )
        _ = try await executeAuthenticated(request)
    }

    // MARK: - Devices

    internal func performListDevices() async throws -> [Device] {
        let request = try await authenticatedRequest(
            method: "GET",
            relativePath: "users/{id}/devices"
        )
        let (data, _) = try await executeAuthenticated(request)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try decoder.decode([Device].self, from: data)
    }

    internal func performRevokeDevice(deviceID: String, name: String?) async throws {
        let body = try JSONEncoder().encode(DeviceRequestBody(deviceID: deviceID, name: name))
        let request = try await authenticatedRequest(
            method: "DELETE",
            relativePath: "users/{id}/devices",
            body: body
        )
        _ = try await executeAuthenticated(request)
    }

    internal func performRenameDevice(deviceID: String, newName: String) async throws {
        let body = try JSONEncoder().encode(
            DeviceRequestBody(deviceID: deviceID, name: newName)
        )
        let request = try await authenticatedRequest(
            method: "PUT",
            relativePath: "users/{id}/devices",
            body: body
        )
        _ = try await executeAuthenticated(request)
    }

    // MARK: - Avatar

    internal func performUploadAvatar(imageData: Data, mimeType: String) async throws -> String {
        // Client-side guard before uploading (mirrors Rauthy's server limits).
        let allowedTypes = ["image/jpeg", "image/png", "image/webp"]
        guard allowedTypes.contains(mimeType.lowercased()) else {
            throw RauthyError.unexpected(AvatarUploadError.unsupportedType(mimeType))
        }
        guard imageData.count <= 5 * 1024 * 1024 else {
            throw RauthyError.unexpected(AvatarUploadError.tooLarge(bytes: imageData.count))
        }
        let boundary = "RauthySwiftBoundary_\(UUID().uuidString)"
        let body = MultipartFormData.build(
            boundary: boundary,
            fieldName: "file",
            filename: "avatar",
            mimeType: mimeType,
            data: imageData
        )
        var request = try await authenticatedRequest(
            method: "PUT",
            relativePath: "users/{id}/picture",
            body: body,
            contentType: "multipart/form-data; boundary=\(boundary)"
        )
        // Server-side accepts the body even without Accept: application/json,
        // but we set it explicitly so error responses are decodable.
        request.setValue("text/plain", forHTTPHeaderField: "Accept")

        let (data, _) = try await executeAuthenticated(request)
        // Server returns the new picture_id as raw text (not JSON).
        guard let pictureID = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines), !pictureID.isEmpty
        else {
            throw RauthyError.server(ServerError(statusCode: 200, message: "empty picture_id"))
        }
        return pictureID
    }

    internal func performDeleteAvatar(pictureID: String) async throws {
        let escaped = pictureID.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)
            ?? pictureID
        let request = try await authenticatedRequest(
            method: "DELETE",
            relativePath: "users/{id}/picture/\(escaped)"
        )
        _ = try await executeAuthenticated(request)
    }

    // MARK: - Passkey conversion

    internal func performConvertToPasskeyOnly() async throws {
        let request = try await authenticatedRequest(
            method: "POST",
            relativePath: "users/{id}/self/convert_passkey",
            body: Data("{}".utf8)
        )
        _ = try await executeAuthenticated(request)
    }

    // MARK: - Account deletion

    internal func performRequestAccountDeletion() async throws {
        let request = try await authenticatedRequest(
            method: "GET",
            relativePath: "users/{id}/self/delete"
        )
        _ = try await executeAuthenticated(request)
    }

    internal func performConfirmAccountDeletion() async throws {
        let request = try await authenticatedRequest(
            method: "DELETE",
            relativePath: "users/{id}/self/delete"
        )
        _ = try await executeAuthenticated(request)
        // Server-side deletion succeeded. Try to drop the local token too —
        // a Keychain failure here doesn't change the outcome (the next API
        // call will 401), but we should at least leave a breadcrumb so an
        // operator wading through logs can tell why a "deleted" account
        // still has stale credentials on disk.
        do {
            try await storage.clear()
        } catch {
            config.logger.warning(
                "Account deletion succeeded server-side but local storage clear failed"
            )
        }
    }
}

/// Client-side avatar validation failures (see `performUploadAvatar`).
private enum AvatarUploadError: Error, Sendable {
    case unsupportedType(String)
    case tooLarge(bytes: Int)
}
