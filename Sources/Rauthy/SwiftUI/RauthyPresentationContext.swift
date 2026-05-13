#if canImport(SwiftUI) && canImport(UIKit) && canImport(AuthenticationServices)
import SwiftUI
import UIKit
import AuthenticationServices

public extension View {
    /// Capture the host `UIWindow` so `RauthyClient.signIn(anchor:)` can
    /// find it without the caller having to plumb it through view state.
    ///
    /// Apply once at your app's root, next to `.environmentObject(authState)`:
    /// ```swift
    /// RauthyAuthGate(...)
    ///     .environmentObject(auth)
    ///     .rauthyPresentationContext()
    /// ```
    ///
    /// Internally, this places a zero-sized UIView in the background that
    /// hooks `didMoveToWindow` to publish the window into the SDK's
    /// internal holder. Calling `auth.signIn()` then "just works."
    ///
    /// v1.0 will extend this to macOS via `NSWindow`. For now, UIKit
    /// platforms only (iOS, tvOS, visionOS, Mac Catalyst).
    func rauthyPresentationContext() -> some View {
        background(RauthyWindowProbe().frame(width: 0, height: 0))
    }
}

private struct RauthyWindowProbe: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView {
        ProbeView()
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        // Re-publish whenever the host re-runs `updateUIView`.
        if let window = uiView.window {
            DispatchQueue.main.async {
                CurrentWindowHolder.shared.window = window
            }
        }
    }
}

private final class ProbeView: UIView {
    override func didMoveToWindow() {
        super.didMoveToWindow()
        if let window = self.window {
            CurrentWindowHolder.shared.window = window
        }
    }
}
#endif
