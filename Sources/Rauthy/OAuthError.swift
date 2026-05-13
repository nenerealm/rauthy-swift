import Foundation

/// Structured OAuth 2.0 error from RFC 6749 Section 5.2 + OIDC extensions.
///
/// Returned by Rauthy's `/token` and `/authorize` endpoints when a request is
/// malformed or denied. Use the `code` for programmatic decisions; `description`
/// is for logging only (never display to end users — it may leak details).
public struct OAuthError: Error, Sendable, Codable, Equatable {
    public let code: Code
    public let description: String?
    public let uri: URL?

    public init(code: Code, description: String? = nil, uri: URL? = nil) {
        self.code = code
        self.description = description
        self.uri = uri
    }

    public enum Code: String, Sendable, Codable, CaseIterable {
        // RFC 6749 §5.2
        case invalidRequest = "invalid_request"
        case invalidClient = "invalid_client"
        case invalidGrant = "invalid_grant"
        case unauthorizedClient = "unauthorized_client"
        case unsupportedGrantType = "unsupported_grant_type"
        case invalidScope = "invalid_scope"
        // RFC 6749 §4.1.2.1
        case accessDenied = "access_denied"
        case serverError = "server_error"
        case temporarilyUnavailable = "temporarily_unavailable"
        // OIDC Core §3.1.2.6
        case interactionRequired = "interaction_required"
        case loginRequired = "login_required"
        case consentRequired = "consent_required"
        case accountSelectionRequired = "account_selection_required"
    }

    private enum CodingKeys: String, CodingKey {
        case code = "error"
        case description = "error_description"
        case uri = "error_uri"
    }
}

/// Server-side error envelope returned by Rauthy's non-OAuth endpoints
/// (e.g., `/users/{id}/self`). Distinguished from `OAuthError` because the
/// shape differs and the recovery path is different.
public struct ServerError: Error, Sendable, Equatable {
    /// HTTP status code (4xx or 5xx).
    public let statusCode: Int

    /// Optional structured error code from Rauthy (e.g., "ConnectionTimeout",
    /// "Validation"). May be absent for generic server errors.
    public let errorCode: String?

    /// Human-readable message from the server. Useful for logging; do not
    /// display verbatim to end users.
    public let message: String?

    public init(statusCode: Int, errorCode: String? = nil, message: String? = nil) {
        self.statusCode = statusCode
        self.errorCode = errorCode
        self.message = message
    }
}
