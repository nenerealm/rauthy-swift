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

    /// Formatted key lookup. Replaces the first occurrence of `%@` in the
    /// resolved string with `arg`. Use this for messages that embed a single
    /// runtime value (HTTP status, OS status, error description).
    ///
    /// Deliberately uses literal substitution rather than `String(format:)`.
    /// `String(format:)` reads garbage memory or crashes if a translator
    /// accidentally writes `%lld`/`%s` where the SDK passes a `String` — and
    /// `.strings` files are user-editable. Manual substitution turns a bad
    /// translation into a cosmetic bug, not a production crash.
    static func string(_ key: String, _ arg: String) -> String {
        let format = string(key)
        guard let range = format.range(of: "%@", options: .literal) else {
            // Translator dropped the placeholder; degrade gracefully by
            // appending the argument so the value still reaches the user.
            return format.isEmpty ? arg : "\(format) \(arg)"
        }
        return format.replacingCharacters(in: range, with: arg)
    }

    /// Resolve the best `.lproj` bundle for the current override (if any),
    /// using Apple's BCP-47 matcher. Returns the main module bundle when no
    /// override is set — Foundation then picks the user's preferred locale.
    ///
    /// Special-cases Chinese: a bare `Locale(identifier: "zh")` would
    /// otherwise miss the `zh-Hans` / `zh-Hant` lprojs because language-code
    /// extraction strips the script tag. We expand to script-tagged candidates
    /// before handing off to Foundation's matcher.
    private static func chooseBundle() -> Bundle {
        guard let override = Rauthy.locale else {
            return .module
        }

        var preferences: [String] = [override.identifier]
        if let lang = override.language.languageCode?.identifier, lang != override.identifier {
            preferences.append(lang)
            // Foundation matches "zh" → "zh-Hans" only when given an explicit
            // script. Inject sensible defaults so callers passing just "zh"
            // don't silently fall back to English.
            if lang == "zh" {
                preferences.append("zh-Hans")
                preferences.append("zh-Hant")
            }
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
