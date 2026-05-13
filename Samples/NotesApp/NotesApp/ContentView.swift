import SwiftUI
import AuthenticationServices

struct ContentView: View {
    @EnvironmentObject var auth: AuthViewModel
    @State private var anchor: ASPresentationAnchor?

    var body: some View {
        ZStack {
            // Invisible probe that captures the host window for ASWebAuth.
            WindowAnchor { window in
                self.anchor = window
            }
            .frame(width: 0, height: 0)

            switch auth.state {
            case .loading:
                ProgressView()
            case .signedOut:
                LoginView(anchor: anchor)
            case .signedIn(let user):
                MainView(user: user)
            }
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
            Text(error)
        }
    }
}
