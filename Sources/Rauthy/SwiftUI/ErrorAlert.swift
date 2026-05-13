#if canImport(SwiftUI)
import SwiftUI

public extension View {
    /// Attach a single error alert that surfaces `RauthyAuthState.lastError`
    /// whenever it becomes non-nil. Dismissing the alert clears the error.
    ///
    /// Apply once at your app root, alongside `.environmentObject(auth)` and
    /// `.rauthyPresentationContext()`:
    ///
    /// ```swift
    /// RauthyAuthGate(...)
    ///     .environmentObject(auth)
    ///     .rauthyPresentationContext()
    ///     .rauthyErrorAlert(auth)
    /// ```
    ///
    /// Title and dismiss-button strings are localized — set
    /// ``Rauthy/locale`` to override the language at runtime. The message is
    /// the underlying `RauthyError`'s `localizedDescription`. For richer copy,
    /// observe `auth.lastError` yourself and present a custom alert.
    func rauthyErrorAlert(_ auth: RauthyAuthState) -> some View {
        modifier(RauthyErrorAlertModifier(auth: auth))
    }
}

private struct RauthyErrorAlertModifier: ViewModifier {
    @ObservedObject var auth: RauthyAuthState

    func body(content: Content) -> some View {
        content
            .alert(
                RauthyL10n.string("ui.errorAlert.title"),
                isPresented: Binding(
                    get: { auth.lastError != nil },
                    set: { newValue in
                        if !newValue { auth.lastError = nil }
                    }
                ),
                presenting: auth.lastError
            ) { _ in
                Button(RauthyL10n.string("ui.errorAlert.dismiss")) {
                    auth.lastError = nil
                }
            } message: { error in
                Text(error.localizedDescription)
            }
    }
}
#endif
