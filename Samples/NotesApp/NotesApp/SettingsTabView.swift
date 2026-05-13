import SwiftUI
import Rauthy

/// Settings tab — locale switching, claim-rule demo, browser flows, sign-out
/// modes, account deletion. Demonstrates:
///
///   - `Rauthy.locale` runtime switching
///   - `.rauthyRequiresRole / Group / Claim` view modifiers
///   - `@RauthyUser` property wrapper (via `@EnvironmentObject` in this sample)
///   - `client.web.openAccountDashboard()`
///   - `signOut(scope:)` with all four scopes
///   - `AccountAPI.requestAccountDeletion()` + `confirmAccountDeletion()`
struct SettingsTabView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    @State private var deletionStep: DeletionStep = .idle
    @State private var deletionConfirm = false
    @State private var signOutScope: SignOutMode = .revokeTokens
    @State private var signOutConfirm = false
    @State private var errorMessage: String?

    enum DeletionStep {
        case idle
        case requested
    }

    enum SignOutMode: String, CaseIterable, Identifiable {
        case local
        case revokeTokens
        case rpInitiated
        case full
        var id: String { rawValue }

        var label: String {
            switch self {
            case .local: return "Local only"
            case .revokeTokens: return "Revoke tokens (RFC 7009)"
            case .rpInitiated: return "RP-Initiated Logout (browser)"
            case .full: return "Full (revoke + RP-Initiated)"
            }
        }

        var description: String {
            switch self {
            case .local:
                return "Clears Keychain only. Server session still alive — refresh tokens on other devices still work."
            case .revokeTokens:
                return "POST /oidc/revoke to invalidate the refresh token server-side, then clear Keychain."
            case .rpInitiated:
                return "Opens the end-session endpoint in ASWebAuthenticationSession. Requires \"notesapp://logged-out\" in Rauthy's allowed post-logout redirects."
            case .full:
                return "Combines revoke + RP-Initiated. Most thorough — clears tokens AND server session via UI."
            }
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                localeSection
                claimDemoSection
                browserSection
                signOutSection
                dangerSection

                if let err = errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Settings")
            .confirmationDialog(
                "Sign out (\(signOutScope.label))?",
                isPresented: $signOutConfirm,
                titleVisibility: .visible
            ) {
                Button("Sign out", role: .destructive) {
                    Task { await performSignOut() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(signOutScope.description)
            }
            .confirmationDialog(
                deletionStep == .idle
                    ? "Request account deletion?"
                    : "Confirm account deletion?",
                isPresented: $deletionConfirm,
                titleVisibility: .visible
            ) {
                Button(
                    deletionStep == .idle ? "Request" : "Delete forever",
                    role: .destructive
                ) {
                    Task { await deletionStep == .idle ? requestDeletion() : confirmDeletion() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(
                    deletionStep == .idle
                        ? "Step 1/2: ask Rauthy to start the deletion flow. Most Rauthy deployments will email you a confirmation link."
                        : "Step 2/2: actually delete the account. This wipes the user, sessions, and tokens. No undo."
                )
            }
        }
    }

    // MARK: - Locale switcher

    private var localeSection: some View {
        Section {
            LocalePickerRow()
        } header: {
            Text("Language")
        } footer: {
            Text(
                "Switches the language of error messages thrown by the SDK and the built-in `.rauthyErrorAlert` strings. Doesn't affect this sample app's own UI text — that's English-only."
            )
        }
    }

    // MARK: - Claim rule live demo

    private var claimDemoSection: some View {
        Section {
            HStack {
                Text("Admin role")
                Spacer()
                Text("Visible below if you have it →").foregroundStyle(.secondary).font(.caption)
            }

            Text("⭐️ You have admin")
                .rauthyRequiresRole("admin")

            HStack {
                Text("Group: users")
                Spacer()
                Text("Visible below if you have it →").foregroundStyle(.secondary).font(.caption)
            }

            Text("👋 You're in the `users` group")
                .rauthyRequiresGroup("users")

            HStack {
                Text("Email verified")
                Spacer()
                Text("Visible below if verified →").foregroundStyle(.secondary).font(.caption)
            }

            Text("✅ Email is verified")
                .rauthyRequiresClaim(.or([.role("admin"), .group("users")]))
        } header: {
            Text("ClaimRule view modifiers")
        } footer: {
            Text(
                "`.rauthyRequiresRole(\"admin\")` etc. read from the @RauthyUser environment. View is removed entirely (not just hidden) if the rule fails."
            )
        }
    }

    // MARK: - Browser flows

    private var browserSection: some View {
        Section {
            Button {
                Task { await openAccountDashboard() }
            } label: {
                Label("Open account dashboard", systemImage: "safari")
            }

            Button {
                Task { await openSubPath("account/devices") }
            } label: {
                Label("Open /account/devices", systemImage: "laptopcomputer.and.iphone")
            }
        } header: {
            Text("Web flows")
        } footer: {
            Text("Opens Rauthy's hosted UI in Safari (keeps your existing rauthy session).")
        }
    }

    // MARK: - Sign-out

    private var signOutSection: some View {
        Section {
            Picker("Mode", selection: $signOutScope) {
                ForEach(SignOutMode.allCases) { mode in
                    Text(mode.label).tag(mode)
                }
            }

            Text(signOutScope.description)
                .font(.caption)
                .foregroundStyle(.secondary)

            Button(role: .destructive) {
                signOutConfirm = true
            } label: {
                Label("Sign out", systemImage: "rectangle.portrait.and.arrow.right")
            }
            .disabled(auth.isBusy)
        } header: {
            Text("Sign out")
        }
    }

    // MARK: - Danger zone

    private var dangerSection: some View {
        Section {
            switch deletionStep {
            case .idle:
                Button(role: .destructive) {
                    deletionConfirm = true
                } label: {
                    Label("Delete my account…", systemImage: "trash")
                }
            case .requested:
                VStack(alignment: .leading, spacing: 8) {
                    Text("Deletion requested. Check your email for the confirmation link.")
                        .font(.subheadline)
                    Button(role: .destructive) {
                        deletionConfirm = true
                    } label: {
                        Label("Confirm deletion (bypass email)", systemImage: "exclamationmark.triangle")
                    }
                    .font(.subheadline)
                }
            }
        } header: {
            Text("Danger zone")
        } footer: {
            Text(
                "Two-step deletion: request, then confirm. Real Rauthy deployments require the email link to click. This sample exposes the second call directly so you can drive the full flow from one device."
            )
        }
    }

    // MARK: - Actions

    private func performSignOut() async {
        errorMessage = nil
        let scope: SignOutScope
        switch signOutScope {
        case .local:
            scope = .local
        case .revokeTokens:
            scope = .revokeTokens
        case .rpInitiated:
            // Requires Rauthy admin to register notesapp://logged-out as an
            // allowed post-logout redirect URI.
            scope = .rpInitiated(postLogoutRedirect: URL(string: "notesapp://logged-out")!)
        case .full:
            scope = .full(postLogoutRedirect: URL(string: "notesapp://logged-out")!)
        }
        await auth.signOut(scope: scope)
    }

    private func openAccountDashboard() async {
        await auth.client.web.openAccountDashboard()
    }

    private func openSubPath(_ path: String) async {
        await auth.client.web.openAccountURL(path: path)
    }

    private func requestDeletion() async {
        do {
            try await auth.client.account.requestAccountDeletion()
            deletionStep = .requested
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func confirmDeletion() async {
        do {
            try await auth.client.account.confirmAccountDeletion()
            // confirmAccountDeletion clears storage on success; force the
            // SwiftUI view tree to re-evaluate.
            await auth.signOut(scope: .local)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

// MARK: - Locale picker

struct LocalePickerRow: View {
    @State private var selection: String = LocalePickerRow.currentIdentifier()

    static let options: [(label: String, id: String)] = [
        (label: "Follow system", id: ""),
        (label: "English (en)", id: "en"),
        (label: "简体中文 (zh-Hans)", id: "zh-Hans"),
        (label: "日本語 (ja)", id: "ja"),
        (label: "Unsupported (de) — falls back", id: "de"),
    ]

    var body: some View {
        Picker("SDK locale", selection: $selection) {
            ForEach(Self.options, id: \.id) { option in
                Text(option.label).tag(option.id)
            }
        }
        .onChange(of: selection) { _, newValue in
            Rauthy.locale = newValue.isEmpty ? nil : Locale(identifier: newValue)
        }
    }

    static func currentIdentifier() -> String {
        Rauthy.locale?.identifier ?? ""
    }
}
