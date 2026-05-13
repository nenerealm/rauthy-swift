#  ``Rauthy``

Client-side Swift SDK for the Rauthy OIDC/OAuth2 identity provider.

## Overview

Rauthy Swift SDK connects SwiftUI iOS/macOS/tvOS/visionOS apps to a
[Rauthy](https://github.com/sebadob/rauthy) server. It handles the full
OAuth 2.0 / OpenID Connect authorization-code flow with PKCE, token
refresh, signature validation, and Rauthy-specific extensions like
passkey management, account self-service, and declarative authorization
via ``ClaimRule``.

Built on Apple's `AuthenticationServices` framework, `CryptoKit`, and
`Security` framework — no third-party crypto dependencies. Single
external dependency: `swift-log` for diagnostic output.

## Topics

### Getting started

- <doc:GettingStarted>

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

### Rauthy-specific features

- ``AccountAPI``
- ``PasskeyAPI``
- ``WebFlows``
- ``Passkey``
- ``Device``

### Errors

- ``RauthyError``
- ``OAuthError``
- ``JWTValidationFailure``
- ``KeychainError``

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
