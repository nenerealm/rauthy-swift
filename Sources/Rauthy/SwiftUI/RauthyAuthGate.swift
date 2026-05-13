#if canImport(SwiftUI)
import SwiftUI

/// Top-level routing view that switches between signed-in, signed-out, and
/// loading states based on `RauthyAuthState.status`.
///
/// Read the auth state from `@EnvironmentObject` — wire your app like:
/// ```swift
/// @StateObject var auth = RauthyAuthState(client: rauthy)
///
/// var body: some Scene {
///     WindowGroup {
///         RauthyAuthGate { user in
///             MainView(user: user)
///         } signedOut: {
///             LoginView()
///         }
///         .environmentObject(auth)
///         .rauthyPresentationContext()
///         .task { await auth.bootstrap() }
///     }
/// }
/// ```
///
/// The loading state shows a `ProgressView()` by default. Pass a custom
/// `loading` builder to override (useful if you want a branded splash).
public struct RauthyAuthGate<SignedIn: View, SignedOut: View, Loading: View>: View {
    @EnvironmentObject private var auth: RauthyAuthState

    let signedIn: (User) -> SignedIn
    let signedOut: () -> SignedOut
    let loading: () -> Loading

    public init(
        @ViewBuilder _ signedIn: @escaping (User) -> SignedIn,
        @ViewBuilder signedOut: @escaping () -> SignedOut,
        @ViewBuilder loading: @escaping () -> Loading = { ProgressView() }
    ) {
        self.signedIn = signedIn
        self.signedOut = signedOut
        self.loading = loading
    }

    public var body: some View {
        switch auth.status {
        case .loading:
            loading()
        case .signedOut:
            signedOut()
        case .signedIn(let user):
            signedIn(user)
        }
    }
}
#endif
