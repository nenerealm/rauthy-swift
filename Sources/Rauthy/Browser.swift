#if canImport(UIKit)
import Foundation
import UIKit

/// Routes the user to Rauthy's hosted account dashboard and other
/// web-based flows that the SDK doesn't (or can't) handle natively.
///
/// Access via `client.web`. All methods open URLs in the system browser
/// (Safari on iOS), where the user authenticates via Rauthy's normal
/// session cookies and uses Rauthy's account UI directly.
///
/// **Why the system browser, not `ASWebAuthenticationSession`?**
/// `ASWebAuthenticationSession` is sandboxed (per-app cookie jar), so the
/// user would have to sign in to Rauthy a second time inside the sheet —
/// bad UX. Opening in Safari means the user keeps their existing Rauthy
/// session if they have one.
public struct WebFlows: Sendable {
    let client: RauthyClient

    public init(client: RauthyClient) {
        self.client = client
    }

    /// Open Rauthy's account dashboard at `<issuer>/account` in Safari.
    /// Useful for "Manage account" links — the user can change their
    /// password, manage passkeys, view event history, etc. without the
    /// SDK having to wrap every API.
    @MainActor
    @discardableResult
    public func openAccountDashboard() async -> Bool {
        let url = client.accountDashboardURL()
        return await UIApplication.shared.open(url)
    }

    /// Open an arbitrary Rauthy account URL in Safari.
    ///
    /// Use this for deep links into the account dashboard (e.g., directly
    /// to `/account/password` or `/account/devices`) when you want to skip
    /// the top-level dashboard view.
    @MainActor
    @discardableResult
    public func openAccountURL(path: String) async -> Bool {
        let url = client.accountSubURL(path: path)
        return await UIApplication.shared.open(url)
    }
}

public extension RauthyClient {
    /// Namespace for web-based account flows. See `WebFlows`.
    var web: WebFlows {
        WebFlows(client: self)
    }
}

extension RauthyClient {
    /// Pure URL composition over `config.issuer` — `config` is `nonisolated let`,
    /// so this helper is callable from any actor context (including @MainActor
    /// in `WebFlows`).
    internal nonisolated func accountDashboardURL() -> URL {
        accountSubURL(path: "account")
    }

    internal nonisolated func accountSubURL(path: String) -> URL {
        let baseString = config.issuer.absoluteString
        let trimmedBase = baseString.hasSuffix("/")
            ? String(baseString.dropLast())
            : baseString
        let rawPath = path.hasPrefix("/") ? String(path.dropFirst()) : path
        let trimmedPath = rawPath.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        // Fall back to the issuer origin rather than force-unwrapping if the
        // composed string somehow fails to parse.
        return URL(string: "\(trimmedBase)/\(trimmedPath)") ?? config.issuer
    }
}
#endif
