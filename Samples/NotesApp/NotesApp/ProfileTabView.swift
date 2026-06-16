import SwiftUI
import Rauthy

/// Profile tab — read-only display of user info, avatar, roles, and groups.
/// Profile / username / avatar *editing* lives in Rauthy's hosted web account
/// dashboard (opened via `WebFlows.openAccountDashboard`), because Rauthy's
/// self-service endpoints require a session cookie / API-key, not an OIDC
/// Bearer token. Demonstrates:
///
///   - reading the `User` snapshot from `@RauthyUser` / RauthyAuthState
///   - `RauthyClient.pictureURL(userID:pictureID:)` for avatar display
///   - `WebFlows.openAccountDashboard()` handoff for account management
struct ProfileTabView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 16) {
                        AvatarView(user: user, size: 100)
                        VStack(spacing: 4) {
                            Text(displayName).font(.title2.bold())
                            if let email = user.email {
                                Text(email).font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                } footer: {
                    Text("Avatar is managed in your Rauthy web account dashboard.")
                }

                Section("Profile") {
                    InfoRow(label: "Username", value: user.preferredUsername ?? "—")
                    InfoRow(label: "Given name", value: user.givenName ?? "—")
                    InfoRow(label: "Family name", value: user.familyName ?? "—")
                    InfoRow(
                        label: "Email verified",
                        value: user.emailVerified == true ? "Yes" : "No"
                    )
                    InfoRow(label: "Language", value: user.locale ?? "default")
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

                Section {
                    Button {
                        Task { await auth.client.web.openAccountDashboard() }
                    } label: {
                        Label("Manage profile in browser", systemImage: "safari")
                    }
                } footer: {
                    Text("Opens Rauthy's web account dashboard to edit your profile, username, and avatar.")
                }

                Section {
                    Button {
                        Task { await auth.refreshUser() }
                    } label: {
                        Label("Refresh from server", systemImage: "arrow.clockwise")
                    }
                    .disabled(auth.isBusy)
                }
            }
            .navigationTitle("Profile")
        }
    }

    private var displayName: String {
        if let n = user.preferredUsername, !n.isEmpty { return n }
        if let g = user.givenName, let f = user.familyName { return "\(g) \(f)" }
        return user.email ?? "Unknown"
    }
}

// MARK: - Avatar view

struct AvatarView: View {
    let user: User
    let size: CGFloat

    var body: some View {
        Group {
            if let url = user.pictureURL {
                AsyncImage(url: url) { phase in
                    switch phase {
                    case .empty:
                        ProgressView()
                    case .success(let image):
                        image.resizable().scaledToFill()
                    case .failure:
                        fallback
                    @unknown default:
                        fallback
                    }
                }
            } else {
                fallback
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
        .overlay(Circle().stroke(.tertiary, lineWidth: 1))
    }

    private var fallback: some View {
        ZStack {
            Circle().fill(.tint.opacity(0.2))
            Text(initials).font(.title.bold()).foregroundStyle(.tint)
        }
    }

    private var initials: String {
        if let n = user.preferredUsername?.first { return String(n).uppercased() }
        if let g = user.givenName?.first { return String(g).uppercased() }
        return "?"
    }
}

// MARK: - Reusable info row

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing)
        }
    }
}
