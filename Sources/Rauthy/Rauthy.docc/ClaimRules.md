# Claim-based authorization

Express "who can use what" with ``ClaimRule``.

## Why

Rauthy's design takes the position that **a valid token alone doesn't
imply access**. Almost every multi-tenant or multi-app Rauthy deployment
needs to gate apps by roles, groups, or other custom claims. The SDK
makes this declarative.

``ClaimRule`` mirrors Rauthy server's `ClaimMapping` enum exactly:

- ``ClaimRule/any`` — every authenticated user matches
- ``ClaimRule/none`` — no one matches
- ``ClaimRule/or(_:)`` — at least one of the claims must hit
- ``ClaimRule/and(_:)`` — all claims must hit

Pair with ``Claim/role(_:)`` and ``Claim/group(_:)`` factories:

```swift
let adminRule: ClaimRule = .or([
    .role("admin"),
    .group("ops"),
])

let premiumRule: ClaimRule = .and([
    .group("paid"),
    .role("verified"),
])
```

## At config time

The two required ``ClaimRule`` values on ``RauthyConfig``:

```swift
RauthyConfig.production(
    issuer: ...,
    clientID: ...,
    redirectURI: ...,
    userClaim: .or([.group("my-app-users")]),     // must satisfy to use the app
    adminClaim: .or([.role("admin")])              // also marks user as admin
)
```

The SDK doesn't currently enforce these at sign-in (that's a v1.1
roadmap item) — they're available as ``RauthySession/isUser`` and
``RauthySession/isAdmin``-style checks. v1.1 will reject tokens that
fail `userClaim` at sign-in time.

## In SwiftUI

Gate any view declaratively:

```swift
AdminPanel()
    .rauthyRequiresClaim(.or([.role("admin")]))
```

Or use shortcut modifiers:

```swift
AdminPanel()
    .rauthyRequiresRole("admin")

PremiumFeature()
    .rauthyRequiresGroup("paid")
```

By default the view is hidden when the rule fails. Pass a `fallback`
view to show something else:

```swift
PremiumFeature()
    .rauthyRequiresClaim(.and([.group("paid"), .role("verified")])) {
        UpgradePrompt()
    }
```

Re-evaluation happens automatically whenever
``RauthyAuthState/status`` changes (e.g., after ``RauthyAuthState/refreshUser()``).

## Manual checks

When you need to branch in non-SwiftUI code:

```swift
let rule: ClaimRule = .or([.role("admin")])
if rule.matches(roles: user.roles, groups: user.groups) {
    // ...
}
```

## What's NOT in ClaimRule

The Swift enum doesn't include a `not` case. Rauthy server's
`ClaimMapping` doesn't support negation either, so omitting it keeps
the client and server in lockstep. If you genuinely need negation,
express the inverse positively (i.e., enumerate the allowed claims
instead of forbidden ones).
