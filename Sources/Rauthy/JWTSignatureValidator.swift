import Foundation
import CryptoKit
import Security

/// Cryptographic signature validation for JWTs.
///
/// Supports Ed25519 (OKP) via CryptoKit and RSA (RS256/384/512) via the
/// Security framework. These are the four algorithms Rauthy advertises in
/// `dpop_signing_alg_values_supported` and uses for ID token signing.
public enum JWTSignatureValidator {
    /// Validate the signature on a parsed JWT against the given key.
    ///
    /// - Throws: `RauthyError.invalidJWT(.signatureInvalid)` on cryptographic
    ///   failure or `.wrongAlgorithm` if the JWK doesn't match the algorithm.
    public static func validate(
        parts: JWTDecoder.Parts,
        algorithm: SigningAlgorithm,
        jwk: JWK
    ) throws {
        switch algorithm {
        case .eddsa:
            try validateEd25519(parts: parts, jwk: jwk)
        case .rs256:
            try validateRSA(parts: parts, jwk: jwk, secAlgorithm: .rsaSignatureMessagePKCS1v15SHA256)
        case .rs384:
            try validateRSA(parts: parts, jwk: jwk, secAlgorithm: .rsaSignatureMessagePKCS1v15SHA384)
        case .rs512:
            try validateRSA(parts: parts, jwk: jwk, secAlgorithm: .rsaSignatureMessagePKCS1v15SHA512)
        }
    }

    private static func validateRSA(
        parts: JWTDecoder.Parts,
        jwk: JWK,
        secAlgorithm: SecKeyAlgorithm
    ) throws {
        guard jwk.kty == "RSA",
              let nString = jwk.n,
              let eString = jwk.e,
              let nData = Data(base64URLEncoded: nString),
              let eData = Data(base64URLEncoded: eString)
        else {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }

        let secKey: SecKey
        do {
            secKey = try RSAPublicKey.make(n: nData, e: eData)
        } catch {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }

        let signedInput = Data(parts.signedInput.utf8)
        var error: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            secKey,
            secAlgorithm,
            signedInput as CFData,
            parts.signature as CFData,
            &error
        )
        if !isValid {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }
    }

    private static func validateEd25519(parts: JWTDecoder.Parts, jwk: JWK) throws {
        guard jwk.kty == "OKP", jwk.crv == "Ed25519" else {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }
        guard let xValue = jwk.x,
              let publicKeyData = Data(base64URLEncoded: xValue)
        else {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }

        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        } catch {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }

        let signedInput = Data(parts.signedInput.utf8)
        let isValid = publicKey.isValidSignature(parts.signature, for: signedInput)
        if !isValid {
            throw RauthyError.invalidJWT(.signatureInvalid)
        }
    }
}
