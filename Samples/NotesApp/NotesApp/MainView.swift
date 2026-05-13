import SwiftUI
import Rauthy

/// Top-level signed-in surface. Routes between four tabs that together
/// exercise every public SDK feature.
struct MainView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    var body: some View {
        TabView {
            ProfileTabView(user: user)
                .tabItem { Label("Profile", systemImage: "person.crop.circle") }

            SecurityTabView(user: user)
                .tabItem { Label("Security", systemImage: "lock.shield") }

            SettingsTabView(user: user)
                .tabItem { Label("Settings", systemImage: "gearshape") }

            DebugTabView(user: user)
                .tabItem { Label("Debug", systemImage: "ladybug") }
        }
    }
}
