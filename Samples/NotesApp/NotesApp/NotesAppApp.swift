import SwiftUI

@main
struct NotesAppApp: App {
    @StateObject private var auth = AuthViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .task { await auth.bootstrap() }
        }
    }
}
