#  ``Rauthy``

Client-side Swift SDK for the Rauthy OIDC/OAuth2 identity provider.

## Overview

Rauthy Swift SDK connects SwiftUI iOS/macOS/tvOS/visionOS apps to a
[Rauthy](https://github.com/sebadob/rauthy) server. It handles the full
OAuth 2.0 / OpenID Connect authorization-code flow with PKCE, token
refresh, signature validation, declarative authorization via
``ClaimRule``, and a handoff to Rauthy's hosted web account dashboard
(``WebFlows``) for profile, device, and passkey management.

Built on Apple's `AuthenticationServices` framework, `CryptoKit`, and
`Security` framework — no third-party crypto dependencies. Single
external dependency: `swift-log` for diagnostic output.

## Topics

### Getting started

- <doc:GettingStarted>
- <doc:Localization>

### Authentication & sessions

- ``RauthyClient``
- ``RauthyConfig``
- ``Token``
- ``IDToken``
- ``User``
- ``SignOutScope``

### Authorization

- ``ClaimRule``
- ``Claim``
- <doc:ClaimRules>

### SwiftUI integration

- ``RauthyAuthState``
- ``RauthyAuthGate``
- ``RauthyUser``
- <doc:SwiftUIIntegration>

### Web account dashboard

- ``WebFlows``

### Errors

- ``RauthyError``
- ``OAuthError``
- ``ServerError``
- ``JWTValidationFailure``
- ``KeychainError``

### Localization

- ``Rauthy``
- <doc:Localization>

### Storage

- ``SessionStorage``
- ``InMemoryStorage``
- ``KeychainStorage``

### Lower-level building blocks

- ``PKCE``
- ``JWTDecoder``
- ``JWTSignatureValidator``
- ``JWTClaimsValidator``
- ``OIDCDiscovery``
- ``JWKSFetcher``
- ``AuthorizationURLBuilder``
- ``WebAuthBridge``
- ``EndSessionURLBuilder``
- ``TokenExchange``
- ``TokenRevocation``
