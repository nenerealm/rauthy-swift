import SwiftUI
import Rauthy

/// Top-level signed-in surface. Routes between three tabs that together
/// exercise the SDK's public surface.
struct MainView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    var body: some View {
        TabView {
            ProfileTabView(user: user)
                .tabItem { Label("Profile", systemImage: "person.crop.circle") }

            SettingsTabView(user: user)
                .tabItem { Label("Settings", systemImage: "gearshape") }

            DebugTabView(user: user)
                .tabItem { Label("Debug", systemImage: "ladybug") }
        }
    }
}
