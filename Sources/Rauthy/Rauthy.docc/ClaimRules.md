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

`userClaim` is **enforced at sign-in**: a user who does not satisfy the
rule is rejected with ``RauthyError/notAuthorized`` and never gets a
session. Pass `.any` to admit any Rauthy user. `adminClaim` is not a gate
— it marks a sub-group of users as admins for your own checks and the
SwiftUI claim gates below.

> Note: ``Claim/group(_:)`` / ``Claim/role(_:)`` rules are evaluated
> against the ID token's `groups` / `roles` claims, which are only present
> when the matching scope was requested. Request the `groups` scope (and
> ensure Rauthy emits `roles`) when gating on them — otherwise use `.any`.

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
