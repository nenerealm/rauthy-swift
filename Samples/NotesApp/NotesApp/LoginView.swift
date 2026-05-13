import SwiftUI
import Rauthy

struct LoginView: View {
    @EnvironmentObject var auth: RauthyAuthState

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

            Text("Server: misspinkelf.com")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(32)
    }
}
