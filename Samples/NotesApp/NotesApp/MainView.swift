import SwiftUI
import Rauthy

struct MainView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    var body: some View {
        NavigationStack {
            List {
                Section("You're signed in") {
                    if let username = user.preferredUsername {
                        LabeledContent("Username", value: username)
                    }
                    if let email = user.email {
                        LabeledContent("Email", value: email)
                    }
                    if let given = user.givenName, let family = user.familyName {
                        LabeledContent("Name", value: "\(given) \(family)")
                    }
                    LabeledContent("User ID", value: user.id)
                        .font(.caption.monospaced())
                    LabeledContent("Subject (sub)", value: user.subject)
                        .font(.caption.monospaced())
                }

                if !user.roles.isEmpty {
                    Section("Roles") {
                        ForEach(user.roles, id: \.self) { role in
                            Label(role, systemImage: "person.badge.shield.checkmark")
                        }
                    }
                }

                if !user.groups.isEmpty {
                    Section("Groups") {
                        ForEach(user.groups, id: \.self) { group in
                            Label(group, systemImage: "person.3")
                        }
                    }
                }

                if let mfa = user.mfaEnabled {
                    Section {
                        LabeledContent("MFA enabled", value: mfa ? "Yes" : "No")
                    }
                }

                Section {
                    Button(role: .destructive) {
                        Task { await auth.signOut(scope: .revokeTokens) }
                    } label: {
                        HStack {
                            Image(systemName: "rectangle.portrait.and.arrow.right")
                            Text("Sign out")
                        }
                    }
                    .disabled(auth.isBusy)
                }
            }
            .navigationTitle(welcomeLine)
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var welcomeLine: String {
        if let username = user.preferredUsername, !username.isEmpty {
            return "Hi, \(username)"
        }
        if let email = user.email, !email.isEmpty {
            return "Hi, \(email)"
        }
        return "Hi there"
    }
}
