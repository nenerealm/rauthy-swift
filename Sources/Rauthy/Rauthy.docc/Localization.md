# Localization

Switch the language of SDK-thrown error messages and built-in SwiftUI strings
at runtime.

## Overview

The SDK ships translations in **English**, **Simplified Chinese (`zh-Hans`)**,
and **Japanese (`ja`)** for every user-facing string it produces:

- ``RauthyError``, ``OAuthError``, ``JWTValidationFailure``, ``KeychainError``,
  and ``ServerError`` — all conform to `LocalizedError`, so
  `error.localizedDescription` returns translated copy.
- The built-in alert from ``SwiftUI/View/rauthyErrorAlert(_:)`` (title +
  dismiss button).

By default, the SDK follows the **user's system locale**. To honor an in-app
language picker without restarting the app, set ``Rauthy/locale``:

```swift
import Rauthy

Rauthy.locale = Locale(identifier: "zh-Hans")
// ...
do {
    try await rauthy.signIn(anchor: window)
} catch let err as RauthyError {
    showAlert(err.localizedDescription)  // 网络不可用,请检查网络连接后重试。
}
```

Set ``Rauthy/locale`` to `nil` to fall back to the system locale.

## Supported languages

The languages shipped in this version:

```swift
Rauthy.supportedLocales
// → [en, zh-Hans, ja]
```

Setting ``Rauthy/locale`` to anything else (e.g. `de`, `fr`, `es`) falls back
to English. Pull requests adding new translations are welcome — each language
is a single `Localizable.strings` file under
`Sources/Rauthy/Resources/<lang>.lproj/`.

## Thread safety

``Rauthy/locale`` is backed by `OSAllocatedUnfairLock` and is safe to read and
write from any actor or thread. Error descriptions are computed synchronously
when `localizedDescription` is accessed, so changing the locale immediately
affects subsequent error displays.

> Note: A `RauthyError` you've already passed to SwiftUI — for example via
> ``RauthyAuthState/lastError`` while ``SwiftUI/View/rauthyErrorAlert(_:)`` is
> showing — won't re-render its title and message until the view next updates.
> Error alerts are transient, so the practical impact is small; the next error
> uses the new locale. If you need live re-rendering, observe ``Rauthy/locale``
> changes yourself and force a view refresh.

## Distribution

The SDK ships translations as SwiftPM resources (`Bundle.module`). This works
when the SDK is consumed via Swift Package Manager (the supported path). If
you re-distribute as an XCFramework, CocoaPods, or vendored sources without
preserving the resource bundle, ``Rauthy/locale`` will return the raw key
(`"error.networkUnavailable"`) instead of localized copy. Stick with SwiftPM
or open an issue if you need another distribution channel.

## What's NOT localized

The SDK is a library, so the translation surface is intentionally narrow:

- **`String(describing: error)`** — raw enum dumps stay in English. Use
  `error.localizedDescription` for user-facing strings.
- **`OAuthError.description` and `ServerError.message`** — these fields carry
  server-supplied text and may leak implementation details. The SDK's
  localized descriptions intentionally use the error code/status, not these
  fields, to avoid surfacing those to end users.
- **Log messages** — `swift-log` output stays in English. Use
  ``RauthyOSLogHandler`` to route logs through OSLog; logs are for developers,
  not end users.
- **DocC documentation** — written in English; translation is non-goal.

## Topics

### Configuration

- ``Rauthy/locale``
- ``Rauthy/supportedLocales``
