import SwiftUI
import Rauthy

struct LoginView: View {
    @EnvironmentObject var auth: RauthyAuthState
    @State private var showLocaleSheet = false

    var body: some View {
        VStack(spacing: 32) {
            Spacer()

            VStack(spacing: 16) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 72))
                    .foregroundStyle(.tint)
                Text("Notes")
                    .font(.largeTitle.bold())
                Text("A Rauthy Swift SDK sample")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(spacing: 12) {
                Button {
                    Task { await auth.signIn() }
                } label: {
                    HStack {
                        if auth.isBusy {
                            ProgressView()
                                .progressViewStyle(.circular)
                                .tint(.white)
                        }
                        Text(auth.isBusy ? "Signing in..." : "Sign in with Rauthy")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(auth.isBusy)

                Button {
                    showLocaleSheet = true
                } label: {
                    Label("Language: \(currentLanguageLabel)", systemImage: "globe")
                        .font(.subheadline)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            VStack(spacing: 4) {
                Text("Server: \(SampleConfig.issuer.host ?? "?")")
                Text("Client ID: \(SampleConfig.clientID)")
            }
            .font(.caption.monospaced())
            .foregroundStyle(.tertiary)
        }
        .padding(32)
        .sheet(isPresented: $showLocaleSheet) {
            LocalePreviewSheet()
        }
    }

    private var currentLanguageLabel: String {
        switch Rauthy.locale?.identifier {
        case "en": return "English"
        case "zh-Hans": return "简体中文"
        case "ja": return "日本語"
        case nil: return "system"
        case let id?: return id
        }
    }
}

/// Lets the user preview SDK i18n before signing in.
struct LocalePreviewSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var selection: String = Rauthy.locale?.identifier ?? ""

    let options: [(label: String, id: String)] = [
        ("Follow system", ""),
        ("English (en)", "en"),
        ("简体中文 (zh-Hans)", "zh-Hans"),
        ("日本語 (ja)", "ja"),
    ]

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Language", selection: $selection) {
                        ForEach(options, id: \.id) { opt in
                            Text(opt.label).tag(opt.id)
                        }
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                }

                Section("Live preview of SDK error messages") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(networkErrorPreview).font(.subheadline)
                        Text(cancelledPreview).font(.subheadline)
                        Text(reauthPreview).font(.subheadline)
                    }
                }
            }
            .navigationTitle("SDK Language")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onChange(of: selection) { _, newValue in
                Rauthy.locale = newValue.isEmpty ? nil : Locale(identifier: newValue)
            }
        }
    }

    // Reading .localizedDescription forces re-evaluation as `selection` (and
    // therefore Rauthy.locale) changes — SwiftUI re-renders the Form.
    private var networkErrorPreview: String {
        "🌐 " + RauthyError.networkUnavailable.localizedDescription
    }
    private var cancelledPreview: String {
        "🚫 " + RauthyError.userCancelled.localizedDescription
    }
    private var reauthPreview: String {
        "🔑 " + RauthyError.reauthenticationRequired.localizedDescription
    }
}
