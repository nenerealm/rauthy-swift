import SwiftUI
import Rauthy

/// Debug tab — raw data dumps for inspection, plus the `@RauthyUser`
/// property wrapper demo. Useful for verifying that:
///
///   - the User snapshot has the fields you expect
///   - `Rauthy.locale` is taking effect
///   - log output is being routed via `RauthyOSLogHandler` to OSLog
///   - tokens are being persisted / refreshed
struct DebugTabView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    @RauthyUser private var rauthyUser

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if let rauthyUser {
                        Text("Resolved via @RauthyUser: \(rauthyUser.id.prefix(8))…")
                            .font(.caption.monospaced())
                    } else {
                        Text("@RauthyUser sees nil — not signed in?")
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("@RauthyUser property wrapper")
                } footer: {
                    Text("Reads the current `User` from the SwiftUI environment that `RauthyAuthGate` provides.")
                }

                Section("Locale state") {
                    InfoRow(
                        label: "Rauthy.locale",
                        value: Rauthy.locale?.identifier ?? "nil (system)"
                    )
                    InfoRow(label: "System locale", value: Locale.current.identifier)
                    InfoRow(
                        label: "Sample error (zh-Hans test)",
                        value: ""
                    )
                    Text(RauthyError.networkUnavailable.localizedDescription)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("User snapshot") {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(userJSON).font(.caption.monospaced())
                    }
                }

                Section("Logs") {
                    Label("SDK logs route via swift-log → OSLog", systemImage: "doc.text")
                        .font(.subheadline)
                    Text(
                        "Open Console.app on your Mac, attach to this device, "
                            + "and filter for subsystem `rauthy.swift` to see live logs. "
                            + "Token contents are NEVER logged."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Section("Token actions") {
                    Button {
                        Task { await refreshNow() }
                    } label: {
                        Label("Force refresh tokens", systemImage: "arrow.clockwise")
                    }
                    .disabled(auth.isBusy)

                    Button {
                        Task { await auth.refreshUser() }
                    } label: {
                        Label("Re-fetch /userinfo", systemImage: "person.crop.circle.badge.questionmark")
                    }
                    .disabled(auth.isBusy)
                }

                Section {
                    NavigationLink {
                        ClaimRuleSandbox(user: user)
                    } label: {
                        Label("Claim-rule sandbox", systemImage: "checkerboard.shield")
                    }
                }
            }
            .navigationTitle("Debug")
        }
    }

    private var userJSON: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(user),
           let string = String(data: data, encoding: .utf8)
        {
            return string
        }
        return "<encode failed>"
    }

    private func refreshNow() async {
        do {
            _ = try await auth.client.refreshSession()
        } catch {
            // RauthyAuthState's signIn() flow handles errors; for manual refresh
            // failures, surface to lastError for the global error alert.
            auth.lastError = error as? RauthyError ?? .unexpected(error)
        }
    }
}

// MARK: - Claim rule sandbox (interactive evaluator)

struct ClaimRuleSandbox: View {
    let user: User

    @State private var roleInput = "admin"
    @State private var groupInput = "users"
    @State private var combinator: Combinator = .or

    enum Combinator: String, CaseIterable, Identifiable {
        case any, none, or, and
        var id: String { rawValue }
    }

    var body: some View {
        Form {
            Section {
                InfoRow(label: "User roles", value: user.roles.joined(separator: ", "))
                InfoRow(label: "User groups", value: user.groups.joined(separator: ", "))
            }

            Section("Rule inputs") {
                TextField("Role", text: $roleInput).autocorrectionDisabled()
                TextField("Group", text: $groupInput).autocorrectionDisabled()
                Picker("Combinator", selection: $combinator) {
                    ForEach(Combinator.allCases) { c in
                        Text(c.rawValue).tag(c)
                    }
                }
            }

            Section("Result") {
                let rule = buildRule()
                LabeledContent("Rule") {
                    Text(String(describing: rule)).font(.caption.monospaced())
                }
                LabeledContent("Matches") {
                    if rule.matches(roles: user.roles, groups: user.groups) {
                        Text("✅ true").foregroundStyle(.green)
                    } else {
                        Text("❌ false").foregroundStyle(.red)
                    }
                }
            }
        }
        .navigationTitle("ClaimRule sandbox")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func buildRule() -> ClaimRule {
        let r = Claim.role(roleInput)
        let g = Claim.group(groupInput)
        switch combinator {
        case .any: return .any
        case .none: return .none
        case .or: return .or([r, g])
        case .and: return .and([r, g])
        }
    }
}
