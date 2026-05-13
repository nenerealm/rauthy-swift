#if canImport(SwiftUI)
import SwiftUI

public extension View {
    /// Show this view only when the current user satisfies the given
    /// `ClaimRule`. Falls back to the (optional) `fallback` view otherwise
    /// — by default, nothing is rendered.
    ///
    /// ```swift
    /// AdminButton()
    ///     .rauthyRequiresClaim(.or([.role("admin")]))
    /// ```
    ///
    /// Evaluation re-runs automatically whenever `RauthyAuthState.status`
    /// changes, so role/group updates propagate to UI without manual wiring.
    func rauthyRequiresClaim<Fallback: View>(
        _ rule: ClaimRule,
        @ViewBuilder fallback: () -> Fallback = { EmptyView() }
    ) -> some View {
        modifier(ClaimGateModifier(rule: rule, fallback: fallback()))
    }

    /// Shorthand for `rauthyRequiresClaim(.or([.role(role)]))`.
    func rauthyRequiresRole<Fallback: View>(
        _ role: String,
        @ViewBuilder fallback: () -> Fallback = { EmptyView() }
    ) -> some View {
        rauthyRequiresClaim(.or([Claim.role(role)]), fallback: fallback)
    }

    /// Shorthand for `rauthyRequiresClaim(.or([.group(group)]))`.
    func rauthyRequiresGroup<Fallback: View>(
        _ group: String,
        @ViewBuilder fallback: () -> Fallback = { EmptyView() }
    ) -> some View {
        rauthyRequiresClaim(.or([Claim.group(group)]), fallback: fallback)
    }
}

private struct ClaimGateModifier<Fallback: View>: ViewModifier {
    let rule: ClaimRule
    let fallback: Fallback
    @EnvironmentObject private var auth: RauthyAuthState

    func body(content: Content) -> some View {
        Group {
            if matches {
                content
            } else {
                fallback
            }
        }
    }

    private var matches: Bool {
        guard case .signedIn(let user) = auth.status else {
            return false
        }
        return rule.matches(roles: user.roles, groups: user.groups)
    }
}
#endif
