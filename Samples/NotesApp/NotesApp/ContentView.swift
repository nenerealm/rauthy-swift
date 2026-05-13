import SwiftUI
import Rauthy

/// Top-level container. Delegates routing to `RauthyAuthGate` and adds an
/// error alert that surfaces `RauthyAuthState.lastError`.
struct ContentView: View {
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        RauthyAuthGate { user in
            MainView(user: user)
        } signedOut: {
            LoginView()
        }
        .alert(
            "Sign-in error",
            isPresented: Binding(
                get: { auth.lastError != nil },
                set: { if !$0 { auth.lastError = nil } }
            ),
            presenting: auth.lastError
        ) { _ in
            Button("OK") { auth.lastError = nil }
        } message: { error in
            Text(String(describing: error))
        }
    }
}
