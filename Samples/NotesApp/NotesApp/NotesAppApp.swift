import SwiftUI
import Rauthy

@main
struct NotesAppApp: App {
    @StateObject private var auth: RauthyAuthState

    init() {
        // Route SDK diagnostic logs through OSLog so they show up in
        // Console.app under subsystem `rauthy.swift`. Demonstrates
        // RauthyOSLogHandler — see DebugTab → "Logs" section.
        RauthyOSLogHandler.bootstrap()

        let client = RauthyClient(
            config: .production(
                issuer: SampleConfig.issuer,
                clientID: SampleConfig.clientID,
                redirectURI: SampleConfig.redirectURI,
                userClaim: .any,
                adminClaim: .or([.role("admin"), .role("rauthy_admin")])
            ),
            storage: KeychainStorage(service: "com.example.notesapp.rauthy")
        )
        _auth = StateObject(wrappedValue: RauthyAuthState(client: client))
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .rauthyPresentationContext()
                .rauthyErrorAlert(auth)
                .task { await auth.bootstrap() }
        }
    }
}
