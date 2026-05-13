import Foundation

/// A single role or group claim used to express authorization rules.
///
/// Mirrors `JwtClaim` in the Rauthy server (`src/api_types/...`).
public struct Claim: Sendable, Codable, Equatable, Hashable {
    public enum Kind: String, Sendable, Codable, CaseIterable {
        case role
        case group
    }

    public let kind: Kind
    public let value: String

    public init(kind: Kind, value: String) {
        self.kind = kind
        self.value = value
    }

    public static func role(_ value: String) -> Self {
        Claim(kind: .role, value: value)
    }

    public static func group(_ value: String) -> Self {
        Claim(kind: .group, value: value)
    }

    /// Evaluate whether this claim is satisfied by the given roles/groups.
    public func matches(roles: [String], groups: [String]) -> Bool {
        switch kind {
        case .role:
            return roles.contains(value)
        case .group:
            return groups.contains(value)
        }
    }
}
