import SwiftUI
import Rauthy

@main
struct NotesAppApp: App {
    @StateObject private var auth = RauthyAuthState(
        client: RauthyClient(
            config: .production(
                issuer: SampleConfig.issuer,
                clientID: SampleConfig.clientID,
                redirectURI: SampleConfig.redirectURI,
                userClaim: .any,
                adminClaim: .none
            ),
            storage: KeychainStorage(service: "com.example.notesapp.rauthy")
        )
    )

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .rauthyPresentationContext()
                .task { await auth.bootstrap() }
        }
    }
}
