#if canImport(AuthenticationServices)
import Foundation
import AuthenticationServices

/// Passkey management — list, register, and delete WebAuthn credentials
/// on the user's Rauthy account.
///
/// Access via `client.passkeys`. Registration uses iOS's
/// `ASAuthorizationPlatformPublicKeyCredentialProvider` and presents the
/// Face ID / Touch ID sheet — requires an `ASPresentationAnchor` (UIWindow).
public struct PasskeyAPI: Sendable {
    let client: RauthyClient

    public init(client: RauthyClient) {
        self.client = client
    }

    /// List the user's registered passkeys.
    public func list() async throws -> [Passkey] {
        try await client.performListPasskeys()
    }

    /// Register a new passkey. Drives the full WebAuthn registration flow:
    ///
    /// 1. POST `/webauthn/register/start` to fetch a creation challenge.
    /// 2. iOS presents a Face ID / Touch ID sheet via `ASAuthorizationController`.
    /// 3. iOS generates a key pair in the Secure Enclave (or platform authenticator).
    /// 4. POST `/webauthn/register/finish` with the signed credential.
    ///
    /// - Parameters:
    ///   - name: User-visible label for the passkey (e.g. "iPhone 17").
    ///     Subject to Rauthy's username regex (alphanumeric + a small
    ///     punctuation set, 1-32 chars).
    ///   - anchor: The window to anchor the system passkey sheet to.
    @MainActor
    public func register(named name: String, anchor: ASPresentationAnchor) async throws {
        // 1. Get creation challenge from server.
        let challenge = try await client.performStartPasskeyRegistration(name: name)

        // 2. Run iOS native registration UI.
        let credential = try await runRegistration(
            challenge: challenge,
            anchor: anchor
        )

        // 3. Submit completed credential to server.
        try await client.performFinishPasskeyRegistration(name: name, credential: credential)
    }

    /// Delete a passkey by its name.
    public func delete(_ passkey: Passkey) async throws {
        try await client.performDeletePasskey(name: passkey.name)
    }

    /// Delete a passkey by its name (alternative when you don't have the full Passkey value).
    public func delete(name: String) async throws {
        try await client.performDeletePasskey(name: name)
    }

    // MARK: - Internal: ASAuthorizationController async bridge

    @MainActor
    private func runRegistration(
        challenge: PasskeyRegistrationChallenge,
        anchor: ASPresentationAnchor
    ) async throws -> RegisteredCredential {
        guard let challengeBytes = Data(base64URLEncoded: challenge.publicKey.challenge) else {
            throw RauthyError.unexpected(PasskeyError.invalidChallengeEncoding)
        }
        guard let userIDBytes = Data(base64URLEncoded: challenge.publicKey.user.id) else {
            throw RauthyError.unexpected(PasskeyError.invalidUserIDEncoding)
        }

        let rpID = challenge.publicKey.rp.id ?? defaultRPID(client.config.issuer)
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: rpID
        )
        let request = provider.createCredentialRegistrationRequest(
            challenge: challengeBytes,
            name: challenge.publicKey.user.name,
            userID: userIDBytes
        )

        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<RegisteredCredential, any Error>) in
            let coordinator = PasskeyRegistrationCoordinator(
                anchor: anchor,
                continuation: continuation
            )
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = coordinator
            controller.presentationContextProvider = coordinator
            coordinator.controller = controller
            controller.performRequests()
        }
    }

    private func defaultRPID(_ issuer: URL) -> String {
        issuer.host ?? "rauthy"
    }
}

public extension RauthyClient {
    /// Namespace for passkey management.
    var passkeys: PasskeyAPI {
        PasskeyAPI(client: self)
    }
}

// MARK: - Internal coordinator for ASAuthorizationController

/// Holds the continuation while ASAuthorizationController runs its
/// delegate-based flow. Self-retains itself so the coordinator stays
/// alive until the delegate callback fires (otherwise it'd be deallocated
/// before the user finishes Face ID).
private final class PasskeyRegistrationCoordinator:
    NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    let anchor: ASPresentationAnchor
    let continuation: CheckedContinuation<RegisteredCredential, any Error>
    var controller: ASAuthorizationController?
    private var retainSelf: PasskeyRegistrationCoordinator?

    init(anchor: ASPresentationAnchor, continuation: CheckedContinuation<RegisteredCredential, any Error>) {
        self.anchor = anchor
        self.continuation = continuation
        super.init()
        self.retainSelf = self
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        defer { retainSelf = nil }

        guard let registration = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            continuation.resume(throwing: RauthyError.unexpected(PasskeyError.unexpectedCredentialType))
            return
        }
        guard let attestationObject = registration.rawAttestationObject else {
            continuation.resume(throwing: RauthyError.unexpected(PasskeyError.missingAttestationObject))
            return
        }
        let credential = RegisteredCredential(
            credentialID: registration.credentialID,
            attestationObject: attestationObject,
            clientDataJSON: registration.rawClientDataJSON
        )
        continuation.resume(returning: credential)
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: any Error
    ) {
        defer { retainSelf = nil }
        if let asError = error as? ASAuthorizationError {
            switch asError.code {
            case .canceled:
                continuation.resume(throwing: RauthyError.userCancelled)
                return
            default:
                break
            }
        }
        continuation.resume(throwing: RauthyError.unexpected(error))
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchor
    }
}

// MARK: - WebAuthn JSON models (private to this file)

/// Parsed `POST /webauthn/register/start` response. Rauthy wraps the
/// standard WebAuthn `PublicKeyCredentialCreationOptions` in a `publicKey`
/// envelope.
internal struct PasskeyRegistrationChallenge: Codable {
    struct PublicKey: Codable {
        let rp: RelyingParty
        let user: User
        let challenge: String       // base64url
        let pubKeyCredParams: [CredentialParam]?
        let timeout: Int?
        let excludeCredentials: [CredentialDescriptor]?
        let authenticatorSelection: AuthenticatorSelection?
        let attestation: String?
    }
    struct RelyingParty: Codable {
        let id: String?
        let name: String
    }
    struct User: Codable {
        let id: String              // base64url
        let name: String
        let displayName: String
    }
    struct CredentialParam: Codable {
        let type: String
        let alg: Int
    }
    struct CredentialDescriptor: Codable {
        let type: String
        let id: String              // base64url
    }
    struct AuthenticatorSelection: Codable {
        let authenticatorAttachment: String?
        let userVerification: String?
        let requireResidentKey: Bool?
        let residentKey: String?
    }

    let publicKey: PublicKey
}

/// What ASAuthorizationController gives us after the Face ID flow completes.
internal struct RegisteredCredential {
    let credentialID: Data
    let attestationObject: Data
    let clientDataJSON: Data
}

/// JSON body for `POST /webauthn/register/finish` per the WebAuthn spec.
internal struct WebauthnRegFinishBody: Codable {
    let passkeyName: String
    let data: RegisterPublicKeyCredentialJSON

    private enum CodingKeys: String, CodingKey {
        case passkeyName = "passkey_name"
        case data
    }
}

/// Standard WebAuthn `navigator.credentials.create()` output shape.
internal struct RegisterPublicKeyCredentialJSON: Codable {
    let id: String              // base64url credentialID
    let rawId: String           // same
    let response: Response
    let type: String            // "public-key"
    let authenticatorAttachment: String?

    struct Response: Codable {
        let clientDataJSON: String   // base64url
        let attestationObject: String // base64url
    }

    init(credential: RegisteredCredential) {
        let credIDBase64 = credential.credentialID.base64URLEncodedString()
        self.id = credIDBase64
        self.rawId = credIDBase64
        self.response = Response(
            clientDataJSON: credential.clientDataJSON.base64URLEncodedString(),
            attestationObject: credential.attestationObject.base64URLEncodedString()
        )
        self.type = "public-key"
        self.authenticatorAttachment = "platform"
    }
}

internal struct WebauthnRegStartBody: Codable {
    let passkeyName: String
    private enum CodingKeys: String, CodingKey {
        case passkeyName = "passkey_name"
    }
}

internal struct WebauthnDeleteBody: Codable {
    // Empty for normal users; server expects {} or {"mfa_mod_token_id": null}.
    // Encoded as empty object.
}

internal enum PasskeyError: Error, Sendable {
    case invalidChallengeEncoding
    case invalidUserIDEncoding
    case unexpectedCredentialType
    case missingAttestationObject
}

// MARK: - RauthyClient internal implementations

extension RauthyClient {
    internal func performListPasskeys() async throws -> [Passkey] {
        let request = try await authenticatedRequest(
            method: "GET",
            relativePath: "users/{id}/webauthn"
        )
        let (data, _) = try await executeAuthenticated(request)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try decoder.decode([Passkey].self, from: data)
    }

    internal func performStartPasskeyRegistration(name: String) async throws -> PasskeyRegistrationChallenge {
        let body = try JSONEncoder().encode(WebauthnRegStartBody(passkeyName: name))
        let request = try await authenticatedRequest(
            method: "POST",
            relativePath: "users/{id}/webauthn/register/start",
            body: body
        )
        let (data, _) = try await executeAuthenticated(request)
        return try JSONDecoder().decode(PasskeyRegistrationChallenge.self, from: data)
    }

    internal func performFinishPasskeyRegistration(
        name: String,
        credential: RegisteredCredential
    ) async throws {
        let webauthnBody = WebauthnRegFinishBody(
            passkeyName: name,
            data: RegisterPublicKeyCredentialJSON(credential: credential)
        )
        let body = try JSONEncoder().encode(webauthnBody)
        let request = try await authenticatedRequest(
            method: "POST",
            relativePath: "users/{id}/webauthn/register/finish",
            body: body
        )
        _ = try await executeAuthenticated(request)
    }

    internal func performDeletePasskey(name: String) async throws {
        // Empty body (mfa_mod_token_id is null for normal authenticated users).
        let body = Data("{}".utf8)
        let request = try await authenticatedRequest(
            method: "DELETE",
            relativePath: "users/{id}/webauthn/delete/\(name)",
            body: body
        )
        _ = try await executeAuthenticated(request)
    }
}
#endif
