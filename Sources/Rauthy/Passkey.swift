import Foundation

/// A registered WebAuthn passkey on the user's Rauthy account.
///
/// Mirrors `PasskeyResponse` from Rauthy's `api_types/src/users.rs`.
public struct Passkey: Sendable, Codable, Equatable, Hashable, Identifiable {
    /// Human-readable label the user gave this passkey (e.g. "iPhone", "Yubikey 1").
    /// Also serves as the identifier for delete operations.
    public let name: String

    /// When the passkey was registered.
    public let registered: Date

    /// When the passkey was most recently used to authenticate.
    public let lastUsed: Date

    /// Whether the passkey requires User Verification (Face ID / Touch ID
    /// every time, vs. simple presence check). `nil` if the server doesn't
    /// know — Rauthy always returns true/false for passkeys it manages.
    public let userVerified: Bool?

    public init(name: String, registered: Date, lastUsed: Date, userVerified: Bool? = nil) {
        self.name = name
        self.registered = registered
        self.lastUsed = lastUsed
        self.userVerified = userVerified
    }

    /// `Identifiable` conformance — passkey names are unique per user in Rauthy.
    public var id: String { name }

    private enum CodingKeys: String, CodingKey {
        case name
        case registered
        case lastUsed = "last_used"
        case userVerified = "user_verified"
    }
}
