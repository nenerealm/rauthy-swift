import Foundation

/// A device with an active Rauthy session.
///
/// Mirrors `DeviceResponse` from Rauthy's `api_types/src/users.rs`. Used by
/// `AccountAPI.devices()` listings and `revokeDevice(_:)` calls.
public struct Device: Sendable, Codable, Equatable, Hashable, Identifiable {
    public let id: String
    public let clientID: String
    public let userID: String?

    /// When the device session was created.
    public let created: Date
    /// When the device's access token expires.
    public let accessExp: Date
    /// When the device's refresh token expires. `nil` if `offline_access` wasn't granted.
    public let refreshExp: Date?

    public let peerIP: String
    /// Human-readable name (defaults to a derived value if the user didn't set one).
    public let name: String

    public init(
        id: String,
        clientID: String,
        userID: String? = nil,
        created: Date,
        accessExp: Date,
        refreshExp: Date? = nil,
        peerIP: String,
        name: String
    ) {
        self.id = id
        self.clientID = clientID
        self.userID = userID
        self.created = created
        self.accessExp = accessExp
        self.refreshExp = refreshExp
        self.peerIP = peerIP
        self.name = name
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case clientID = "client_id"
        case userID = "user_id"
        case created
        case accessExp = "access_exp"
        case refreshExp = "refresh_exp"
        case peerIP = "peer_ip"
        case name
    }
}
