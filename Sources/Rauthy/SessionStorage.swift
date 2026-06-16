import Foundation

/// Abstract token persistence backend.
///
/// v1.0 is single-account: there is at most one `Token` stored at a time.
/// Multi-account support is deferred to v1.5+ (will add `allIDs`,
/// `defaultID`, and per-ID accessors at that time, in an additive way).
public protocol SessionStorage: Sendable {
    /// Persist the given token. Replaces any previously-stored token.
    func save(_ token: Token) async throws

    /// Load the previously-stored token, if any.
    func load() async throws -> Token?

    /// Remove any stored token. Idempotent — does not throw when no token exists.
    func clear() async throws
}

// MARK: - Default factory

extension SessionStorage where Self == KeychainStorage {
    /// Returns a Keychain-backed storage with the given service name.
    /// Convenience over calling `KeychainStorage(service:)` directly when
    /// you want SDK-default account naming and no access group.
    public static func keychain(
        service: String = "com.rauthy.swift"
    ) -> KeychainStorage {
        KeychainStorage(service: service)
    }
}

// MARK: - In-memory implementation (always available)

/// An in-memory storage backend that holds a single token in memory.
///
/// Use for tests and for cases where token persistence across app restarts
/// is undesirable (kiosk mode, ephemeral sessions). Production apps that
/// want the user to stay signed in across launches should use
/// `KeychainStorage` instead.
public actor InMemoryStorage: SessionStorage {
    private var token: Token?

    public init() {}

    public func save(_ token: Token) async throws {
        self.token = token
    }

    public func load() async throws -> Token? {
        token
    }

    public func clear() async throws {
        token = nil
    }
}

// MARK: - Keychain implementation

/// Keychain-backed token storage. Uses `kSecClassGenericPassword` with
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — readable in
/// background tasks (after the first device unlock) but never leaves the
/// device and is not iCloud-synced.
///
/// Stores a single token under a fixed account name. Multi-account support
/// arrives in v1.5+.
public actor KeychainStorage: SessionStorage {
    private let service: String
    private let account: String
    private let accessGroup: String?

    public init(
        service: String = "com.rauthy.swift",
        account: String = "default",
        accessGroup: String? = nil
    ) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }

    public func save(_ token: Token) async throws {
        let data = try encodeToken(token)
        var attributes = baseQuery()
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let addStatus = SecItemAdd(attributes as CFDictionary, nil)
        switch addStatus {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            // Item already exists — update its value.
            let update: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
            let updateStatus = SecItemUpdate(
                baseQuery() as CFDictionary,
                update as CFDictionary
            )
            if updateStatus != errSecSuccess {
                throw RauthyError.keychainError(mapStatus(updateStatus))
            }
        default:
            throw RauthyError.keychainError(mapStatus(addStatus))
        }
    }

    public func load() async throws -> Token? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { return nil }
            return try decodeToken(data)
        case errSecItemNotFound:
            return nil
        default:
            throw RauthyError.keychainError(mapStatus(status))
        }
    }

    public func clear() async throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        // errSecItemNotFound is idempotent-fine: clearing a missing item is OK.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw RauthyError.keychainError(mapStatus(status))
        }
    }

    // MARK: Internal helpers

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            // Use the modern data-protection keychain. Implied on iOS; on
            // macOS this opts into the iOS-style keychain instead of the
            // legacy file-based one. (macOS note: items written before this
            // change won't be found — the token is simply re-obtained via
            // refresh / re-login.)
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    private func encodeToken(_ token: Token) throws -> Data {
        do {
            return try JSONEncoder().encode(token)
        } catch {
            throw RauthyError.unexpected(KeychainEncodingError.encode)
        }
    }

    private func decodeToken(_ data: Data) throws -> Token {
        do {
            return try JSONDecoder().decode(Token.self, from: data)
        } catch {
            throw RauthyError.unexpected(KeychainEncodingError.decode)
        }
    }

    private func mapStatus(_ status: OSStatus) -> KeychainError {
        switch status {
        case errSecItemNotFound:
            return .itemNotFound
        case errSecDuplicateItem:
            return .duplicateItem
        case errSecAuthFailed:
            return .accessDenied
        case errSecInteractionNotAllowed:
            return .requiresUserPresence
        default:
            return .osStatus(status)
        }
    }
}

private enum KeychainEncodingError: Error, Sendable {
    case encode
    case decode
}
