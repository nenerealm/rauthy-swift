import Foundation

/// A declarative authorization rule that mirrors Rauthy server's `ClaimMapping`.
///
/// Used in two places:
///   1. `RauthyConfig.userClaim` / `adminClaim` — gate which authenticated
///      users may use this app at all.
///   2. SwiftUI `.rauthyRequiresClaim(_:)` modifier — declaratively show or
///      hide views based on the current user's roles/groups.
///
/// Use `.any` to explicitly admit any authenticated user (no claim check).
/// Use `.none` to deny everyone.
///
/// Note: this enum has no `.not` case in v1.0 — it matches Rauthy server's
/// `ClaimMapping` exactly. Negation can be expressed by inverting
/// the rule at the call site, or added in a future minor release if a real
/// use case emerges.
public indirect enum ClaimRule: Sendable, Codable, Equatable {
    /// Any authenticated user matches. Equivalent to "no claim check."
    case any
    /// No user matches. Equivalent to "always deny."
    case none
    /// At least one of the claims must match.
    case or([Claim])
    /// All claims must match.
    case and([Claim])

    /// Evaluate this rule against a user's roles and groups.
    public func matches(roles: [String], groups: [String]) -> Bool {
        switch self {
        case .any:
            return true
        case .none:
            return false
        case .or(let claims):
            return claims.contains { $0.matches(roles: roles, groups: groups) }
        case .and(let claims):
            // Empty AND must fail closed (an empty allSatisfy is vacuously
            // true). Use `.any` to deliberately admit everyone.
            return !claims.isEmpty && claims.allSatisfy { $0.matches(roles: roles, groups: groups) }
        }
    }
}
