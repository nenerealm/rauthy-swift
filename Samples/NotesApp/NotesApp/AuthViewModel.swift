import Foundation
import Rauthy
import AuthenticationServices

/// Wraps `RauthyClient` for SwiftUI consumption. Holds auth state, exposes
/// imperative sign-in/sign-out methods, and surfaces errors to the UI.
///
/// In v1.0 the SDK will ship its own `RauthyAuthState` with the same shape —
/// this file demonstrates the v0.1 pattern apps can copy.
@MainActor
final class AuthViewModel: ObservableObject {
    enum State: Equatable {
        case loading
        case signedOut
        case signedIn(User)
    }

    @Published private(set) var state: State = .loading
    @Published var lastError: String?
    @Published private(set) var isBusy = false

    let client: RauthyClient

    init() {
        let config = RauthyConfig.production(
            issuer: SampleConfig.issuer,
            clientID: SampleConfig.clientID,
            redirectURI: SampleConfig.redirectURI,
            userClaim: .any,
            adminClaim: .none
        )
        self.client = RauthyClient(
            config: config,
            storage: KeychainStorage(service: "com.example.notesapp.rauthy")
        )
    }

    /// Called once at app launch. Tries to restore a previously-stored token
    /// and fetch the user. Falls back to signedOut on any failure.
    func bootstrap() async {
        do {
            if try await client.restoreSession() != nil {
                let user = try await client.fetchUser()
                state = .signedIn(user)
            } else {
                state = .signedOut
            }
        } catch {
            // Restore-or-fetch failed (token expired without refresh, server down,
            // etc.). Treat as signed out — user can sign in again.
            state = .signedOut
        }
    }

    /// Drive the full PKCE flow. Requires an anchor (UIWindow) to host the
    /// ASWebAuthenticationSession sheet.
    func signIn(anchor: ASPresentationAnchor) async {
        isBusy = true
        defer { isBusy = false }

        do {
            _ = try await client.signIn(anchor: anchor)
            let user = try await client.fetchUser()
            state = .signedIn(user)
            lastError = nil
        } catch RauthyError.userCancelled {
            // User dismissed the sheet — not an error, just stay on login screen.
        } catch {
            lastError = describe(error)
        }
    }

    /// Local sign-out + revoke. Clears Keychain and invalidates the server-side
    /// session via Rauthy's /oidc/revoke endpoint.
    func signOut() async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await client.signOut(scope: .revokeTokens)
        } catch {
            // Even if revoke failed (network down, server angry), clear local
            // state so the user isn't trapped in a broken signed-in state.
            try? await client.signOut(scope: .local)
            lastError = describe(error)
        }
        state = .signedOut
    }

    private func describe(_ error: any Error) -> String {
        if let err = error as? RauthyError {
            return String(describing: err)
        }
        return error.localizedDescription
    }
}
