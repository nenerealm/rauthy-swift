import SwiftUI
import Rauthy

/// Top-level container. `.rauthyErrorAlert` (attached in NotesAppApp) handles
/// the error surface globally — this view just routes between signed-in and
/// signed-out states.
struct ContentView: View {
    var body: some View {
        RauthyAuthGate { user in
            MainView(user: user)
        } signedOut: {
            LoginView()
        }
    }
}
