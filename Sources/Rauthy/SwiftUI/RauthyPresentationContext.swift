#if canImport(SwiftUI) && canImport(AuthenticationServices)
import SwiftUI
import AuthenticationServices

#if canImport(UIKit)
import UIKit

public extension View {
    /// Capture the host window so `RauthyClient.signIn(anchor:)` can
    /// find it without the caller having to plumb it through view state.
    ///
    /// Apply once at your app's root, next to `.environmentObject(authState)`:
    /// ```swift
    /// RauthyAuthGate(...)
    ///     .environmentObject(auth)
    ///     .rauthyPresentationContext()
    /// ```
    ///
    /// Internally, this places a zero-sized view in the background that
    /// hooks `didMoveToWindow` (UIKit) or `viewDidMoveToWindow` (AppKit)
    /// to publish the host window into the SDK's internal holder. Calling
    /// `auth.signIn()` then "just works."
    ///
    /// - Note: The host window is stored in a process-global holder
    ///   (last-attached-window-wins). Correct for single-window apps;
    ///   multi-window / multi-scene apps (iPadOS, macOS) should anchor per
    ///   scene — a per-scene API is planned.
    func rauthyPresentationContext() -> some View {
        background(RauthyWindowProbe().frame(width: 0, height: 0))
    }
}

private struct RauthyWindowProbe: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView {
        ProbeView()
    }

    func updateUIView(_ uiView: UIView, context: Context) {
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

#elseif canImport(AppKit)
import AppKit

public extension View {
    /// macOS variant — captures the host `NSWindow` via `NSViewRepresentable`.
    /// Same semantics as the iOS version.
    func rauthyPresentationContext() -> some View {
        background(RauthyMacWindowProbe().frame(width: 0, height: 0))
    }
}

private struct RauthyMacWindowProbe: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        ProbeView()
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if let window = nsView.window {
            DispatchQueue.main.async {
                CurrentWindowHolder.shared.window = window
            }
        }
    }
}

private final class ProbeView: NSView {
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let window = self.window {
            CurrentWindowHolder.shared.window = window
        }
    }
}

#endif
#endif
