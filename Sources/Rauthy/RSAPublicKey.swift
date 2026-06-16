import Foundation
import Security

/// Helpers for constructing Apple `SecKey` objects from RSA public-key
/// components (modulus and exponent), as they appear in JWK form.
///
/// Used by `JWTSignatureValidator` for RS256/384/512 signature verification.
///
/// Apple's Security framework expects RSA public keys in **PKCS#1 DER format**:
/// ```
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```
/// This file handles the DER encoding (and decoding, for tests).
enum RSAPublicKey {
    /// Build a `SecKey` from raw modulus and exponent bytes.
    ///
    /// Both inputs are big-endian unsigned integers as they appear in a JWK
    /// (base64url-decoded). Leading zero bytes are tolerated and stripped.
    static func make(n: Data, e: Data) throws -> SecKey {
        var contents = Data()
        contents.append(encodeASN1Integer(n))
        contents.append(encodeASN1Integer(e))

        var der = Data([0x30])  // SEQUENCE tag
        der.append(encodeASN1Length(contents.count))
        der.append(contents)

        let normalizedN = positiveInteger(n)
        let bitSize = normalizedN.count * 8
        guard bitSize >= 2048 else {
            throw RSAPublicKeyError.creationFailed(
                "RSA modulus is \(bitSize) bits; minimum 2048 required"
            )
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: bitSize,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, &error) else {
            let message = error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
            throw RSAPublicKeyError.creationFailed(message)
        }
        return key
    }

    /// Parse a PKCS#1 `RSAPublicKey` DER blob back into `(n, e)`.
    ///
    /// Only used by tests — given an Apple-generated SecKey, you can call
    /// `SecKeyCopyExternalRepresentation` to get PKCS#1 DER, then use this
    /// to extract `(n, e)` for round-trip testing of `make(n:e:)`.
    static func parse(der: Data) throws -> (n: Data, e: Data) {
        let bytes = Array(der)
        var index = 0
        try expectTag(0x30, bytes, &index)         // SEQUENCE
        _ = try readLength(bytes, &index)
        try expectTag(0x02, bytes, &index)         // INTEGER n
        let nLen = try readLength(bytes, &index)
        guard index + nLen <= bytes.count else {
            throw RSAPublicKeyError.parseError("n length exceeds data")
        }
        var nData = Data(bytes[index..<(index + nLen)])
        index += nLen
        try expectTag(0x02, bytes, &index)         // INTEGER e
        let eLen = try readLength(bytes, &index)
        guard index + eLen <= bytes.count else {
            throw RSAPublicKeyError.parseError("e length exceeds data")
        }
        let eData = Data(bytes[index..<(index + eLen)])
        // Strip leading zero pad on n (DER positive-integer convention).
        if nData.first == 0x00 {
            nData.removeFirst()
        }
        return (n: nData, e: eData)
    }

    // MARK: - DER primitives

    private static func encodeASN1Integer(_ data: Data) -> Data {
        let content = positiveInteger(data)
        var out = Data([0x02])      // INTEGER tag
        out.append(encodeASN1Length(content.count))
        out.append(content)
        return out
    }

    /// Normalize raw big-endian bytes for ASN.1 INTEGER encoding:
    /// strip leading zeros, then prepend `0x00` if the high bit is set (so
    /// the value is unambiguously positive).
    private static func positiveInteger(_ data: Data) -> Data {
        var bytes = Array(data)
        while bytes.count > 1 && bytes.first == 0x00 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        }
        return Data(bytes)
    }

    private static func encodeASN1Length(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        }
        if length < 256 {
            return Data([0x81, UInt8(length)])
        }
        if length < 65536 {
            return Data([0x82, UInt8(length >> 8), UInt8(length & 0xFF)])
        }
        return Data([
            0x83,
            UInt8((length >> 16) & 0xFF),
            UInt8((length >> 8) & 0xFF),
            UInt8(length & 0xFF),
        ])
    }

    private static func expectTag(_ tag: UInt8, _ bytes: [UInt8], _ index: inout Int) throws {
        guard index < bytes.count, bytes[index] == tag else {
            throw RSAPublicKeyError.parseError(
                "expected tag 0x\(String(tag, radix: 16)) at index \(index)"
            )
        }
        index += 1
    }

    private static func readLength(_ bytes: [UInt8], _ index: inout Int) throws -> Int {
        guard index < bytes.count else {
            throw RSAPublicKeyError.parseError("unexpected end of data")
        }
        let first = bytes[index]
        index += 1
        if first < 0x80 {
            return Int(first)
        }
        let numBytes = Int(first & 0x7F)
        guard numBytes <= 8 else {
            throw RSAPublicKeyError.parseError(
                "DER length uses \(numBytes) bytes; refusing (overflow guard)"
            )
        }
        var length = 0
        for _ in 0..<numBytes {
            guard index < bytes.count else {
                throw RSAPublicKeyError.parseError("unexpected end in length encoding")
            }
            length = (length << 8) | Int(bytes[index])
            index += 1
        }
        return length
    }
}

enum RSAPublicKeyError: Error, Sendable {
    case creationFailed(String)
    case parseError(String)
}
