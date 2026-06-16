#if canImport(SwiftUI) && canImport(AuthenticationServices)
import SwiftUI
import AuthenticationServices

/// SwiftUI-friendly façade over `RauthyClient`. Exposes `@Published` auth
/// state for declarative UIs, drives sign-in/sign-out, and reads the host
/// `UIWindow` (set via `.rauthyPresentationContext()`) automatically.
///
/// Typical wiring:
/// ```swift
/// @StateObject var auth = RauthyAuthState(client: rauthy)
///
/// var body: some Scene {
///     WindowGroup {
///         RauthyAuthGate { user in MainView(user: user) } signedOut: { LoginView() }
///             .environmentObject(auth)
///             .rauthyPresentationContext()
///             .task { await auth.bootstrap() }
///     }
/// }
/// ```
@MainActor
public final class RauthyAuthState: ObservableObject {
    /// What the SwiftUI view tree should display right now.
    public enum Status: Sendable, Equatable {
        /// Bootstrap hasn't completed yet (just-launched, or in-progress).
        case loading
        /// No active session — show a login screen.
        case signedOut
        /// Authenticated. Render a user-facing UI.
        case signedIn(User)
    }

    @Published public private(set) var status: Status = .loading
    @Published public var lastError: RauthyError?
    @Published public private(set) var isBusy: Bool = false

    public let client: RauthyClient

    /// Single-flight guard so concurrent `.task`-triggered bootstraps coalesce.
    private var bootstrapTask: Task<Void, Never>?

    public init(client: RauthyClient) {
        self.client = client
    }

    /// The current presentation anchor captured by `.rauthyPresentationContext()`.
    /// Pass this to SDK calls that require an anchor outside the built-in
    /// sign-in flow — e.g. `PasskeyAPI.register(named:anchor:)`:
    ///
    /// ```swift
    /// guard let anchor = auth.presentationAnchor else { return }
    /// try await auth.client.passkeys.register(named: name, anchor: anchor)
    /// ```
    ///
    /// `nil` until a SwiftUI view modified with `.rauthyPresentationContext()`
    /// has been attached to a window.
    public var presentationAnchor: ASPresentationAnchor? {
        CurrentWindowHolder.shared.window
    }

    /// Restore any previously-saved session. Fails **closed**: if the server
    /// has invalidated the session (401), the user is signed out and local
    /// storage cleared; a locally-cached token is only trusted when the
    /// failure was a genuine network outage. Idempotent / single-flight, so
    /// it is safe to call from `.task` (which may re-run on view identity
    /// changes). Call once at app launch.
    public func bootstrap() async {
        if let existing = bootstrapTask {
            return await existing.value
        }
        let task = Task { await self.runBootstrap() }
        bootstrapTask = task
        await task.value
        bootstrapTask = nil
    }

    private func runBootstrap() async {
        lastError = nil
        guard (try? await client.restoreSession()) ?? nil != nil else {
            status = .signedOut
            return
        }
        do {
            status = .signedIn(try await client.fetchUser())
        } catch RauthyError.reauthenticationRequired {
            // Server has invalidated the session — fail closed.
            try? await client.signOut(scope: .local)
            status = .signedOut
        } catch RauthyError.networkUnavailable {
            // Genuine offline: fall back to the locally-stored, still-valid
            // ID token so a flaky network does not bounce the user to login.
            if let user = await userFromCurrentToken() {
                status = .signedIn(user)
            } else {
                status = .signedOut
            }
        } catch {
            status = .signedOut
        }
    }

    /// Drive the full PKCE sign-in flow. Requires `.rauthyPresentationContext()`
    /// to have run somewhere in the view hierarchy.
    ///
    /// - Parameter prefersEphemeralWebBrowserSession: forwarded to
    ///   `RauthyClient.signIn(anchor:prefersEphemeralWebBrowserSession:)`.
    ///   See its docs for when to enable.
    public func signIn(prefersEphemeralWebBrowserSession: Bool = false) async {
        guard let anchor = CurrentWindowHolder.shared.window else {
            lastError = .missingPresentationContext
            return
        }
        lastError = nil
        isBusy = true
        defer { isBusy = false }
        do {
            _ = try await client.signIn(
                anchor: anchor,
                prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
            )
            var user: User? = try? await client.fetchUser()
            if user == nil {
                user = await userFromCurrentToken()
            }
            if let user {
                status = .signedIn(user)
            } else {
                // signIn returned (so a valid token is in storage), but we
                // couldn't materialize a User from /userinfo OR from a local
                // ID token. This is almost always a network blip — surface
                // it as such rather than .reauthenticationRequired, which
                // implies the user did something wrong. A retry (or next
                // app launch's bootstrap) will recover.
                status = .signedOut
                lastError = .networkUnavailable
            }
        } catch RauthyError.userCancelled {
            // User dismissed the sheet — not an error.
        } catch let err as RauthyError {
            lastError = err
        } catch {
            lastError = .unexpected(error)
        }
    }

    /// Sign out. Defaults to `.local` (no network). Use `.revokeTokens` for
    /// server-side revoke, or `.rpInitiated` / `.full` for the OIDC end-session
    /// browser flow (which requires `.rauthyPresentationContext()`).
    public func signOut(scope: SignOutScope = .local) async {
        isBusy = true
        defer { isBusy = false }
        let anchor = CurrentWindowHolder.shared.window
        do {
            try await client.signOut(scope: scope, anchor: anchor)
            status = .signedOut
            lastError = nil
        } catch let err as RauthyError {
            // Even on failure, drop the user to signed-out state so they
            // aren't stuck. Clear local storage as a last resort.
            try? await client.signOut(scope: .local)
            status = .signedOut
            lastError = err
        } catch {
            try? await client.signOut(scope: .local)
            status = .signedOut
            lastError = .unexpected(error)
        }
    }

    /// Fetch a fresh /userinfo and update `status` with the new user.
    /// Returns the new user, or nil on failure (state isn't changed in that case).
    @discardableResult
    public func refreshUser() async -> User? {
        guard case .signedIn = status else { return nil }
        do {
            let user = try await client.fetchUser()
            status = .signedIn(user)
            return user
        } catch let err as RauthyError {
            lastError = err
            return nil
        } catch {
            lastError = .unexpected(error)
            return nil
        }
    }

    /// Synthesize a `User` from the currently-stored ID token, if any.
    /// Used as a fallback when /userinfo is unreachable but a valid local
    /// token exists.
    private func userFromCurrentToken() async -> User? {
        guard let token = try? await client.restoreSession(),
              !token.isExpired(),
              let idToken = token.idToken
        else { return nil }
        return User(idToken: idToken)
    }
}

/// Internal singleton that bridges SwiftUI's view hierarchy and
/// `RauthyClient.signIn(anchor:)`. Set by `.rauthyPresentationContext()`.
///
/// `weak` reference: the window outlives the holder, no retain cycles.
@MainActor
internal final class CurrentWindowHolder {
    static let shared = CurrentWindowHolder()
    weak var window: ASPresentationAnchor?
    private init() {}
}
#endif
