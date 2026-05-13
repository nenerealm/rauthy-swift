import Foundation
import os.lock

/// Top-level namespace for SDK-wide configuration that isn't tied to a single
/// `RauthyClient` instance.
public enum Rauthy {
    private static let _locale = OSAllocatedUnfairLock<Locale?>(initialState: nil)

    /// Override the locale used by SDK-provided error messages (the
    /// `errorDescription` returned through `LocalizedError`) and the SDK's
    /// built-in SwiftUI UI strings.
    ///
    /// Default `nil` follows the system / user locale. Set this when your app
    /// has an in-app language picker that should affect SDK-thrown errors,
    /// without restarting the process:
    ///
    /// ```swift
    /// Rauthy.locale = Locale(identifier: "zh-Hans")
    /// // ...
    /// } catch let err as RauthyError {
    ///     showAlert(err.localizedDescription)  // "网络不可用,请检查网络连接后重试。"
    /// }
    /// ```
    ///
    /// Reads and writes are thread-safe via `os_unfair_lock`. Safe to set
    /// from any actor.
    ///
    /// See ``supportedLocales`` for the languages the SDK ships translations
    /// for. Any other value falls back to English.
    public static var locale: Locale? {
        get { _locale.withLock { $0 } }
        set { _locale.withLock { $0 = newValue } }
    }

    /// Locales the SDK ships translations for. Anything else falls back to
    /// English.
    public static let supportedLocales: [Locale] = [
        Locale(identifier: "en"),
        Locale(identifier: "zh-Hans"),
        Locale(identifier: "ja"),
    ]
}

/// Internal string-lookup helper. Resolves the right `.lproj` bundle based on
/// `Rauthy.locale`, then forwards to `Bundle.localizedString(forKey:...)`.
///
/// Keys live in `Sources/Rauthy/Resources/<lang>.lproj/Localizable.strings`.
internal enum RauthyL10n {
    /// Plain key lookup. Falls back to the key itself if no translation exists
    /// (which is also how Apple's NSLocalizedString behaves by default).
    static func string(_ key: String) -> String {
        chooseBundle().localizedString(forKey: key, value: key, table: nil)
    }

    /// Formatted key lookup (`%lld`, `%@`, etc.). Use this for messages that
    /// embed runtime values like HTTP status codes.
    ///
    /// Locale is intentionally NOT passed to `String(format:)` — we don't want
    /// digit grouping on status codes (HTTP 25,300 looks like a typo, not a
    /// status). The localized format string controls translation; argument
    /// rendering stays POSIX.
    static func string(_ key: String, _ args: any CVarArg...) -> String {
        let format = string(key)
        return String(format: format, arguments: args)
    }

    /// Resolve the best `.lproj` bundle for the current override (if any),
    /// using Apple's BCP-47 matcher. Returns the main module bundle when no
    /// override is set — Foundation then picks the user's preferred locale.
    private static func chooseBundle() -> Bundle {
        guard let override = Rauthy.locale else {
            return .module
        }

        var preferences: [String] = [override.identifier]
        if let lang = override.language.languageCode?.identifier {
            preferences.append(lang)
        }

        let candidates = Bundle.preferredLocalizations(
            from: Bundle.module.localizations,
            forPreferences: preferences
        )

        for candidate in candidates {
            if let path = Bundle.module.path(forResource: candidate, ofType: "lproj"),
               let bundle = Bundle(path: path) {
                return bundle
            }
        }
        return .module
    }
}
