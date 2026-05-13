import SwiftUI
import UIKit
import AuthenticationServices

/// Captures a `UIWindow` reference from a SwiftUI view hierarchy so it can be
/// passed to `ASWebAuthenticationSession` as a presentation anchor.
///
/// SwiftUI doesn't expose the host window directly. This wraps a zero-sized
/// `UIView` and reaches up the responder chain to grab `view.window`. The
/// callback fires whenever the view's window changes (e.g., when the app
/// supports multiple scenes).
///
/// In v1.0 of the SDK, this becomes `.rauthyPresentationContext()` modifier —
/// see the design doc.
struct WindowAnchor: UIViewRepresentable {
    let onAnchor: (ASPresentationAnchor) -> Void

    func makeUIView(context: Context) -> UIView {
        let view = ProbeView()
        view.onWindowChanged = onAnchor
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        if let window = uiView.window {
            onAnchor(window)
        }
    }
}

private final class ProbeView: UIView {
    var onWindowChanged: ((ASPresentationAnchor) -> Void)?

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if let window = self.window {
            onWindowChanged?(window)
        }
    }
}
