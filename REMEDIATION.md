# Rauthy Swift SDK 修复指南 / Remediation Guide

> 配套文档：[`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)（审查报告 / 发现清单）
> 本文档说明**每条发现的具体代码级修复方案**。
> **状态：未应用。** 本次仅交付文档，所有改动待批准后再执行。

---

## 0. 使用说明

- 本指南**按文件组织**（便于逐文件应用）。每个改动标注其发现 ID（如 SEC-M01）与严重度。
- 代码片段为 Swift 6。`现状` = 当前代码，`修复` = 改后代码。
- ⚠️ 标注的是**跨文件依赖**或**行为变更**，应用时需一并处理。

### 应用顺序（建议）

| 批次 | 包含 | 说明 |
|------|------|------|
| **批次 1（行为正确性）** | SEC-M01, SEC-M02 | 改变"你以为有、实际没有"的保护 |
| **批次 2（防御纵深·小改动）** | SEC-M03, SEC-M04, SEC-L07, SEC-L08, SEC-L17 | 低风险、收益明确 |
| **批次 3（测试网）** | SEC-M05, SEC-M06, SEC-L23~L27 | 需先做"可注入接缝"再补测 |
| **批次 4（其余）** | 其余 low / info | 按需排期 |

### ⚠️ 跨文件依赖一览

1. **SEC-M01** 新增 `RauthyError.notAuthorized` → 须同时改 `RauthyError.swift`（枚举 + `==` + `errorDescription`）＋ 三个 `Localizable.strings` ＋ `RauthyClient.swift`（抛出处）。
2. **SEC-M05/M06** 的"可注入接缝"在 `RauthyClient.swift` 引入 `internal completeSignIn(...)` 与 `internal validateIDToken(...)` → 测试文件依赖这两个 internal 符号。
3. **SEC-L11** `LocalDevURLSession.make` 增加 `issuerHost` 参数 → `RauthyClient.swift` 调用处需传 `config.issuer.host`（建议给默认值 `nil`，避免硬性破坏）。

### ⚠️ 行为变更警告

- **SEC-M01 实施后**：不满足 `userClaim` 的用户**将无法登录**（抛 `.notAuthorized`）。若你的 app 用了非 `.any` 的 `userClaim`，必须确认已请求对应 `groups`/`roles` scope（否则 token 无该 claim → 全员误拒），或改用 `.any`。
- **SEC-L12 / SEC-I04**：改变 URLSession 缓存策略 / macOS Keychain 后端，属保守且正确的方向，但会让"改动前已缓存/已存"的旧数据失效一次（token 可经刷新/重登恢复，无数据丢失风险）。

---

## 批次 1 + 2 + 4：源码修复（逐文件）

### 📄 `Sources/Rauthy/PKCE.swift` — SEC-M04 🟡

**现状**（`init()`，约 26-27 行）：
```swift
var bytes = [UInt8](repeating: 0, count: 32)
_ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
```
**修复**：检查返回值，失败即 fail-closed（平台级不可恢复故障，trap 可接受）：
```swift
var bytes = [UInt8](repeating: 0, count: 32)
guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
    preconditionFailure("SecRandomCopyBytes failed — refusing to generate a predictable PKCE verifier")
}
```
> 为什么：丢弃返回值意味着 RNG 失败时会用"全零缓冲区"当随机数，生成可预测的 `code_verifier`，击穿 PKCE。

---

### 📄 `Sources/Rauthy/AuthorizationURLBuilder.swift` — SEC-M04 🟡

**现状**（`randomToken`，约 36-38 行）：
```swift
var bytes = [UInt8](repeating: 0, count: byteCount)
_ = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
return Data(bytes).base64URLEncodedString()
```
**修复**：
```swift
var bytes = [UInt8](repeating: 0, count: byteCount)
guard SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes) == errSecSuccess else {
    preconditionFailure("SecRandomCopyBytes failed — refusing to generate a predictable state/nonce")
}
return Data(bytes).base64URLEncodedString()
```
> 为什么：`state`(防 CSRF) 与 `nonce`(防重放) 同样必须不可预测。

---

### 📄 `Sources/Rauthy/RSAPublicKey.swift` — SEC-L04 🔵 + SEC-I03 ⚪

**SEC-L04（RSA 最小长度）**——`make(n:e:)` 内，`let normalizedN = positiveInteger(n)` 之后：
```swift
let normalizedN = positiveInteger(n)
let bitSize = normalizedN.count * 8
guard bitSize >= 2048 else {                                   // ← 新增
    throw RSAPublicKeyError.creationFailed("RSA modulus is \(bitSize) bits; minimum 2048 required")
}
```
**SEC-I03（`readLength` 整数溢出，仅测试路径）**——`let numBytes = Int(first & 0x7F)` 之后：
```swift
let numBytes = Int(first & 0x7F)
guard numBytes <= 8 else {                                     // ← 新增
    throw RSAPublicKeyError.parseError("DER length uses \(numBytes) bytes; refusing (overflow guard)")
}
```

---

### 📄 `Sources/Rauthy/JWTClaimsValidator.swift` — SEC-L01 🔵 + SEC-I01 ⚪

在 `validate(_:against:now:)` 内：

**SEC-L01（多 aud 须有 azp，OIDC §3.1.3.7 规则4）**——紧接 aud 检查（约 77 行）之后：
```swift
// OIDC Core §3.1.3.7 规则4：含多个受众时应要求 azp 存在。
if claims.aud.count > 1 && claims.azp == nil {
    throw RauthyError.invalidJWT(.wrongAzp(expected: context.clientID, got: "<missing>"))
}
```
**SEC-I01（拒绝未来 iat）**——紧接 exp 检查（约 89 行）之后：
```swift
// iat 明显在未来（超出 leeway）→ 拒绝。复用 .notYetValid。
if claims.iat.timeIntervalSince(now) > context.leeway {
    throw RauthyError.invalidJWT(.notYetValid)
}
```
> SEC-I02（EdDSA at_hash 用 SHA-256）：**不改代码**——SHA-256 符合 OIDC 家族惯例，且 Rauthy 不发 at_hash（死代码）。仅建议在 `computeAtHash` 处补一行注释说明这是有意为之。

---

### 📄 `Sources/Rauthy/RauthyClient.swift` — SEC-M01 / M03 / M05 / M06 / L02 / L03 / L12 / L17 🟡🔵

这是改动最集中的文件。

#### SEC-M05 / M06：可注入接缝（重构 `signIn`）

把 `validateIDToken` 由 `private` 改为 `internal`，并把 `signIn` 中"拿到回调 URL 之后"的逻辑抽成可单测的 `internal completeSignIn(...)`：

```swift
// 新增：可被测试直接调用（无需 ASWebAuthenticationSession / anchor）
internal func completeSignIn(
    callbackURL: URL,
    state: String,
    nonce: String,
    pkce: PKCE,
    discovery: OpenIDConfiguration
) async throws -> Token {
    let (code, returnedState) = try AuthorizationURLBuilder.parseCallback(callbackURL)
    guard returnedState == state else {                       // ← SEC-M06 测试目标
        config.logger.warning("State mismatch — possible CSRF attempt")
        throw RauthyError.stateMismatch
    }
    let token = try await TokenExchange.exchange(
        code: code, verifier: pkce.codeVerifier,
        config: config, discovery: discovery, session: urlSession
    )
    if let idToken = token.idToken {
        try await validateIDToken(                            // ← SEC-M05 测试目标
            idToken, accessToken: token.accessToken, nonce: nonce, discovery: discovery
        )
        // —— SEC-M01：userClaim 强制执行（见下）——
        guard config.userClaim.matches(
            roles: idToken.payload.roles, groups: idToken.payload.groups
        ) else {
            config.logger.info("Sign-in rejected: user does not satisfy userClaim")
            throw RauthyError.notAuthorized                   // ⚠️ 依赖 RauthyError 新增 case
        }
    } else if config.scopes.contains("openid") {
        config.logger.warning("openid scope requested but no id_token returned")
    }
    try await storage.save(token)
    config.logger.info("Sign-in succeeded")
    config.logger.debug("Sign-in token issued", metadata: ["sub": "\(token.idToken?.payload.sub ?? "unknown")"])
    return token
}
```
然后 `signIn(...)` 末尾原本那段（解析回调→换码→验证→存盘）替换为一行：
```swift
let callbackURL = try await WebAuthBridge.authenticate(...)   // 保持不变
return try await completeSignIn(
    callbackURL: callbackURL, state: state, nonce: nonce, pkce: pkce, discovery: discovery
)
```

#### SEC-M01：userClaim 强制执行
见上 `completeSignIn` 中的 `guard config.userClaim.matches(...)`。⚠️ 行为变更见顶部警告。同时建议在 `RauthyConfig` 注释中说明 scope 依赖（见 RauthyConfig 一节）。

#### SEC-M03：refresh 后重新验证 id_token
`validateIDToken` 签名把 `nonce: String` 改为 `nonce: String?`（`Context.nonce` 本就是 `String?`，直接透传）。然后在 `refresh(_:)` 的 `Task` 内，`TokenExchange.refresh` 之后、`storage.save(new)` 之前：
```swift
let new = try await TokenExchange.refresh(...)
if let idToken = new.idToken {
    try await self.validateIDToken(                            // ← 新增
        idToken, accessToken: new.accessToken, nonce: nil, discovery: discovery
    )
}
try await storage.save(new)
```

#### SEC-L02：算法白名单先于验签
`validateIDToken` 内，调用 `JWTSignatureValidator.validate` **之前**插入：
```swift
guard config.allowedAlgorithms.contains(idToken.header.alg) else {
    throw RauthyError.invalidJWT(.wrongAlgorithm(
        allowed: Array(config.allowedAlgorithms), got: idToken.header.alg.rawValue))
}
```

#### SEC-L03：JWKS 选 key 时过滤 use/kty/alg
`validateIDToken` 内，把 `keySet.key(for: kid)` 换成更严格的选择（加私有 helper）：
```swift
func selectKey(_ set: JWKSet) -> JWK? {
    set.keys.first { jwk in
        guard jwk.kid == kid else { return false }
        if let use = jwk.use, use != "sig" { return false }          // 仅签名用途
        switch idToken.header.alg {                                   // kty 与算法族匹配
        case .rs256, .rs384, .rs512: return jwk.kty == "RSA"
        case .eddsa:                 return jwk.kty == "OKP" && jwk.crv == "Ed25519"
        }
    }
}
var matchingKey = selectKey(keySet)
// kid-miss 重拉后同样用 selectKey(...)
```

#### SEC-L12：生产环境不用 `URLSession.shared`（避免磁盘缓存 /userinfo）
`defaultURLSession(for:)` 的非 localDev 分支：
```swift
// 现状：return .shared
let configuration = URLSessionConfiguration.default
configuration.urlCache = nil
configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
return URLSession(configuration: configuration)
```

#### SEC-L17：`.full` 登出失败不记原始错误体
`signOut` 的 `.full` 分支 revoke 失败处（约 277-280 行）：
```swift
// 现状：metadata: ["error": "\(error)"]  ← 可能把服务器响应体写进 .public 日志
config.logger.warning("Token revocation failed during .full sign-out; continuing with RP-Initiated")
```

---

### 📄 `Sources/Rauthy/RauthyError.swift` — SEC-M01 🟡

1. 枚举新增（建议放在 "User-driven outcomes" 区）：
```swift
/// 用户通过了 IdP 认证，但不满足 app 配置的 `userClaim`，不允许使用本 app。
case notAuthorized
```
2. `==` 的"简单 case"列表里加上 `(.notAuthorized, .notAuthorized)`：
```swift
case (.userCancelled, .userCancelled),
     (.notAuthorized, .notAuthorized),          // ← 新增
     ...
```
3. `errorDescription` 的 switch 里加：
```swift
case .notAuthorized:
    return RauthyL10n.string("error.notAuthorized")
```

---

### 📄 `Sources/Rauthy/Resources/{en,zh-Hans,ja}.lproj/Localizable.strings` — SEC-M01 🟡

各加一行（与现有 `error.*` 风格一致）：
```strings
// en
"error.notAuthorized" = "You don't have access to this app. Please contact your administrator.";
// zh-Hans
"error.notAuthorized" = "你没有使用此应用的权限,请联系管理员。";
// ja
"error.notAuthorized" = "このアプリを使用する権限がありません。管理者にお問い合わせください。";
```

---

### 📄 `Sources/Rauthy/RauthyConfig.swift` — SEC-L06 🔵 + SEC-M01(文档) 🟡

**SEC-L06**：给 `.production` 工厂加 `allowedAlgorithms` 参数并透传：
```swift
public static func production(
    issuer: URL, clientID: String, redirectURI: URL,
    scopes: [String] = ["openid", "profile", "email"],
    allowedAlgorithms: Set<SigningAlgorithm> = Set(SigningAlgorithm.allCases),  // ← 新增
    userClaim: ClaimRule, adminClaim: ClaimRule,
    logger: Logger = Logger(label: "rauthy.swift")
) -> Self {
    Self(issuer: issuer, clientID: clientID, redirectURI: redirectURI, scopes: scopes,
         allowedAlgorithms: allowedAlgorithms,                                   // ← 新增
         userClaim: userClaim, adminClaim: adminClaim, logger: logger)
}
```
**SEC-M01（文档）**：把 `userClaim`/`adminClaim` 的注释从"gates whether a user may use this app"（现在时承诺）改为说明**现已在 `signIn` 强制执行**，并补一句：
> `.group(...)`/`.role(...)` 规则要求 token 携带对应 claim——请确保请求了 `groups`/`roles` scope（Rauthy 的 `groups` 是受支持 scope；roles 视 Rauthy 配置而定）。否则请用 `.any`。

---

### 📄 `Sources/Rauthy/OAuthError.swift` — SEC-L18 🔵

`decodeServerErrorResponse` 第三层兜底，截断 body：
```swift
// 现状：message: String(data: data, encoding: .utf8)
let capped = String(data: data, encoding: .utf8).map { String($0.prefix(512)) }
return .server(ServerError(statusCode: statusCode, message: capped))
```

---

### 📄 `Sources/Rauthy/OSLogHandler.swift` — SEC-L19 🔵

静态消息保持 `.public`、**动态 metadata 值改 `.private`**（保留可读性的同时让潜在敏感值脱敏）。把 `log(...)` 里的 switch 改为消息与 metadata 分开标注隐私级别：
```swift
switch level {
case .trace, .debug:
    logger.debug("\(message, privacy: .public)\(metaString, privacy: .private)")
case .info, .notice:
    logger.info("\(message, privacy: .public)\(metaString, privacy: .private)")
case .warning:
    logger.warning("\(message, privacy: .public)\(metaString, privacy: .private)")
case .error:
    logger.error("\(message, privacy: .public)\(metaString, privacy: .private)")
case .critical:
    logger.fault("\(message, privacy: .public)\(metaString, privacy: .private)")
}
```
> `metaString` 仍以 ` key=value` 形式构造，仅隐私级别从 `.public` 降为 `.private`。

---

### 📄 `Sources/Rauthy/ClaimRule.swift` — SEC-L05 🔵

空 `.and` 改为 fail-closed：
```swift
case .and(let claims):
    return !claims.isEmpty && claims.allSatisfy { $0.matches(roles: roles, groups: groups) }
```
> 空 `.or([])` 已正确为 `false`，无需改。"放行所有人"应显式用 `.any`。

---

### 📄 `Sources/Rauthy/PasskeyAPI.swift` — SEC-L07 🔵 + SEC-L09 🔵

**SEC-L07**：`performDeletePasskey` 对 name 百分号编码（与 `deleteAvatar` 一致）：
```swift
let escaped = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
let request = try await authenticatedRequest(
    method: "DELETE", relativePath: "users/{id}/webauthn/delete/\(escaped)", body: Data("{}".utf8))
```
**SEC-L09**：完整 `mfa_mod_token_id` 流程属新功能（需服务端联调），不在本轮实现。建议在 `register`/`delete` 文档注释补一句限制：
> 注：当前实现面向普通账户；受 MFA 保护的账户管理 passkey 需 `mfa_mod_token_id`，尚未支持（v1.1 TODO）。

---

### 📄 `Sources/Rauthy/MultipartFormData.swift` — SEC-L08 🔵

`build(...)` 开头拒绝头部注入字符（调用方目前用固定值，故 precondition 可接受；也可改为清洗）：
```swift
for value in [fieldName, filename, mimeType] {
    precondition(
        !value.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\"" }),
        "multipart header value must not contain CR, LF, or double-quote")
}
```

---

### 📄 `Sources/Rauthy/RauthyClient+Account.swift` — SEC-L10 🔵 + SEC-L17 🔵

**SEC-L10**：`performUploadAvatar` 开头加客户端预校验：
```swift
private enum AvatarError: Error, Sendable { case unsupportedType, tooLarge }

let allowed = ["image/jpeg", "image/png", "image/webp"]
guard allowed.contains(mimeType.lowercased()) else { throw RauthyError.unexpected(AvatarError.unsupportedType) }
guard imageData.count <= 5 * 1024 * 1024 else { throw RauthyError.unexpected(AvatarError.tooLarge) }
```
**SEC-L17**：账户删除后清本地失败处（约 254-257 行）改结构化日志，不记 `"\(error)"`：
```swift
config.logger.warning("Account deleted server-side but local storage clear failed (will 401 on next call)")
```

---

### 📄 `Sources/Rauthy/SwiftUI/RauthyAuthState.swift` — SEC-M02 / L13 / L14 / L16 🟡🔵

**SEC-M02 + L13 + L16**：重写 `bootstrap()` 为 fail-closed + 区分错误 + 单飞 + 清错误：
```swift
private var bootstrapTask: Task<Void, Never>?

public func bootstrap() async {
    if let t = bootstrapTask { return await t.value }          // SEC-L13 单飞
    let task = Task { await self.doBootstrap() }
    bootstrapTask = task
    await task.value
    bootstrapTask = nil
}

private func doBootstrap() async {
    lastError = nil                                            // SEC-L16
    guard (try? await client.restoreSession()) ?? nil != nil else { status = .signedOut; return }
    do {
        status = .signedIn(try await client.fetchUser())
    } catch RauthyError.reauthenticationRequired {            // SEC-M02：服务端已踢出 → 失效拦截
        try? await client.signOut(scope: .local)
        status = .signedOut
    } catch RauthyError.networkUnavailable {                  // 仅网络问题才乐观回退
        status = (await userFromCurrentToken()).map(Status.signedIn) ?? .signedOut
    } catch {
        status = .signedOut
    }
}
```
并让 `userFromCurrentToken()` 在 token 过期时返回 nil：
```swift
guard let token = try? await client.restoreSession(),
      !token.isExpired(),                                      // ← 新增过期检查
      let idToken = token.idToken else { return nil }
```
**SEC-L16**：`signIn(...)` 入口同样加 `lastError = nil`。
**SEC-L14**：`signIn` 成功后若 user 物化失败，不要发 `.signedOut`——因为 token 已落盘。优先用 `userFromCurrentToken()` 维持 `.signedIn`，仅真无会话时才 `.signedOut`。

---

### 📄 `Sources/Rauthy/WebAuthBridge.swift` — SEC-L28 🔵

让 `AnchorProvider` 在回调前不被释放——在 completion handler 内强引用它：
```swift
) { callbackURL, error in
    withExtendedLifetime(provider) {}     // ← 保活 provider 直到回调触发（与 PasskeyAPI 自持有等价）
    if let error { continuation.resume(throwing: Self.map(error)); return }
    ...
}
```

---

### 📄 `Sources/Rauthy/SwiftUI/RauthyPresentationContext.swift` — SEC-L15 🔵

不改行为，补文档注释说明单窗口假设：
> 注：`CurrentWindowHolder` 是进程级单例，采用"最后一个附着的窗口"。单窗口 app 正确；iPad/Mac 多窗口场景应改为按场景(scene)持有 anchor（v1.x 计划）。

---

### 📄 `Sources/Rauthy/SessionStorage.swift` — SEC-I04 ⚪

`baseQuery()` 加数据保护 Keychain（统一 iOS/macOS 行为）：
```swift
var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
    kSecUseDataProtectionKeychain as String: true,   // ← 新增；iOS 隐含,macOS 显式启用现代 Keychain
]
```
> ⚠️ macOS 上此项会切换 Keychain 后端，改动前已存的旧条目将读不到（token 可经重登/刷新恢复，无数据丢失）。

---

### 📄 `Sources/Rauthy/LocalDevURLSession.swift` — SEC-L11 🔵

自签 CA 信任仅对 issuer host 生效。给 `make` 加 `issuerHost` 参数（默认 nil 以免硬性破坏），delegate 据此判断：
```swift
static func make(settings: RauthyConfig.LocalDevSettings, issuerHost: String? = nil) -> URLSession { ... 把 issuerHost 传给 TrustingDelegate ... }

// TrustingDelegate.urlSession(_:didReceive:) 开头：
if let expected = issuerHost, challenge.protectionSpace.host != expected {
    completionHandler(.performDefaultHandling, nil); return
}
```
> ⚠️ 跨文件：`RauthyClient.defaultURLSession` 的调用处传 `issuerHost: config.issuer.host`。

---

### 📄 `Sources/Rauthy/Browser.swift` — SEC-I05 ⚪

`accountSubURL(path:)` 对 path 编码并消除强解包：
```swift
internal nonisolated func accountSubURL(path: String) -> URL {
    let trimmedBase = config.issuer.absoluteString.hasSuffix("/")
        ? String(config.issuer.absoluteString.dropLast()) : config.issuer.absoluteString
    let trimmedPath = (path.hasPrefix("/") ? String(path.dropFirst()) : path)
        .addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
    return URL(string: "\(trimmedBase)/\(trimmedPath)") ?? config.issuer    // 失败兜底回 issuer,不再强解包
}
```

---

### 📄 `README.md` — SEC-L20 🔵 + SEC-L21 🔵

- **SEC-L20**：快速开始的 `RauthyClient(config: ...)` 显式传 `storage: .keychain()`，或在示例下方注明"默认 `InMemoryStorage` 重启即丢，生产请用 `.keychain()`"。
- **SEC-L21**：删除"组合子 `.and` / `.or` / `.not`"中的 **`.not`**（`ClaimRule` 无此 case）。

---

### 📄 `Sources/Rauthy/Rauthy.docc/GettingStarted.md` + `ClaimRules.md` — SEC-M01 🟡

- 把"SDK 现在就会强制 userClaim"说清楚（与 SEC-M01 实现一致），删除 `ClaimRules.md` 中**不存在**的 `RauthySession/isUser`、`isAdmin` 引用。
- 增补 scope 依赖说明（`.group/.role` 需对应 scope）。

---

## 批次 3：测试（`Tests/RauthyTests/RauthyTests.swift`）

> 依赖 SEC-M05/M06 引入的 `internal completeSignIn(...)` 与 `internal validateIDToken(...)`。沿用现有 `MockURLProtocol` 与 `@testable import Rauthy`。

| ID | 新增测试 |
|----|---------|
| SEC-M06 | `completeSignIn` 传入 `state` 不匹配的回调 URL → 抛 `.stateMismatch` 且未存盘；匹配 → 继续换码 |
| SEC-M05 | 经 `completeSignIn`/`validateIDToken`（MockURLProtocol 桩 JWKS）：kid 命中成功 / kid-miss 触发**恰好一次**重拉后成功 / 重拉仍失败 → `.signatureInvalid` / 验签先于 claims |
| SEC-M01 | `userClaim` 不满足 → `completeSignIn` 抛 `.notAuthorized`、未存盘；`.any` → 通过 |
| SEC-M03 | refresh 返回的 id_token 签名无效 → refresh 抛错、未存盘 |
| SEC-L05 | `ClaimRule.and([]).matches(...) == false`，`.or([]) == false`，`.any == true` |
| SEC-L23 | `azp != clientID` → `.wrongAzp`；`azp == clientID` 通过；缺 azp 单 aud 通过 |
| SEC-L24 | `JWTDecoder.parseIDToken`：`alg:"none"` / `"HS256"` / 非法 JSON → `.malformedJWT` |
| SEC-L25 | `JWKSFetcher.fetch`：200 正常解码 / 500 → `.server` / 传输错误 → `.networkUnavailable` / 坏 JSON → 抛错 |
| SEC-L26 | `KeychainStorage` 的 OSStatus→`KeychainError` 映射（直接驱动映射函数）|
| SEC-L27 | `RSAPublicKey` parse→make 往返字节相等；含前导零字节的 2048-bit；非法 DER 负例 |

---

## 验证清单（应用后）

```bash
cd rauthy-swift
swift build
swift test --no-parallel        # Rauthy.locale 是进程级全局,必须串行
```
- [ ] 全部编译通过、测试通过
- [ ] `git diff` 复核每处改动符合本指南
- [ ] 针对 SEC-M01 行为变更，确认你的 app/样例的 `userClaim` 与 scope 配置
- [ ] 在真实服务器 `your-rauthy.example.com` 跑一次登录→刷新→登出冒烟测试
