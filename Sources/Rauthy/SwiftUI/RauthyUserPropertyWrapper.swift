#if canImport(SwiftUI)
import SwiftUI

/// SwiftUI property wrapper that exposes the currently signed-in `User`
/// (or `nil` if signed-out / loading) from the ambient `RauthyAuthState`.
///
/// Use inside any view that's reachable from a `RauthyAuthGate { ... }`
/// branch — i.e. anywhere `@EnvironmentObject` resolves a `RauthyAuthState`:
///
/// ```swift
/// struct ProfileView: View {
///     @RauthyUser var user
///
///     var body: some View {
///         if let user {
///             Text("Hi, \(user.email ?? "anonymous")")
///         }
///     }
/// }
/// ```
///
/// The wrapper re-renders the view whenever `RauthyAuthState.status`
/// changes (sign-in, sign-out, refresh-user).
@MainActor
@propertyWrapper
public struct RauthyUser: DynamicProperty {
    @EnvironmentObject private var auth: RauthyAuthState

    public init() {}

    public var wrappedValue: User? {
        if case .signedIn(let user) = auth.status {
            return user
        }
        return nil
    }
}
#endif
