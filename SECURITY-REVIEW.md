# Rauthy Swift SDK 安全审查报告 / Security Review

> 审查对象：`rauthy-swift` v1.0（OIDC/OAuth2 客户端 SDK，Swift 6 严格并发）
> 审查日期：2026-06-14
> 审查方式：多 agent 静态审查（10 维度 / 54 agent，每条发现独立对抗性核验）＋ 人工精读全部安全核心 ＋ 对真实服务器 `your-rauthy.example.com` 的只读协议验证
> 结论：**无严重(critical)/高危(high)漏洞**；6 中危(medium)、28 低危(low)、7 信息(info)；3 条经核验为误报已剔除。整体代码质量在水准之上。

---

## 1. 概述 / Executive Summary

这是一个质量明显在水准之上的认证 SDK。最容易出致命错误的地方——**ID token 签名验证(signature validation)、PKCE、OIDC claim 校验、单飞刷新(single-flight refresh)、Keychain 存储**——都实现正确。没有发现任何可被远程利用的 critical/high 级别漏洞。

发现按**核验后真实严重度**分布：

| 严重度 | 数量 | 性质 |
|--------|------|------|
| 🔴 critical | 0 | —— |
| 🟠 high | 0 | —— |
| 🟡 medium | 6 | 2 条真正的"失效放行"(fail-open)、2 条防御纵深(defense-in-depth)、2 条核心路径缺测试 |
| 🔵 low | 28 | 加固、健壮性、文档一致性 |
| ⚪ info | 7 | 观察项 / 可选优化 |
| ✅ 误报 | 3 | 被对抗性核验否决 |

**术语速查**（本报告面向初学者，关键英文术语首次出现处给出中文解释）：
- **fail-open / fail-closed（失效放行 / 失效拦截）**：出错时"放行"是危险默认；"拦截"才安全。
- **id_token（身份令牌）**：服务器签名的 JWT，装着"你是谁"。客户端必须**验签**才能信任。
- **PKCE**：授权码流程的防截获机制；其 `code_verifier`/`state`/`nonce` 必须不可预测。
- **claims（声明）**：token 里的字段，如 `iss`(签发者)/`aud`(受众)/`exp`(过期)/`sub`(用户 ID)。
- **security boundary（安全边界）**：真正强制鉴权的地方。本 SDK 的安全边界在**服务器**；客户端的角色/组门禁只是便利性(convenience)。

---

## 2. 审查方法论 / Methodology

三路独立交叉，降低漏报与误报：

1. **多 agent 静态审查**：10 个维度（加密正确性、OIDC/OAuth2 协议合规、token 生命周期与存储/传输安全、Swift 6 并发、授权逻辑 fail-closed 性、账户/Passkey API、SwiftUI 集成、错误与日志泄露、API 设计与崩溃式 DoS、测试覆盖）。每个维度一个专家 agent。
2. **对抗性核验(adversarial verification)**：每一条发现都由独立的"怀疑者"agent 去**证伪**——独立重读代码、寻找别处的缓解控制、在信任模型下重新评估严重度、检查推荐修复是否正确。3 条因此被否决。
3. **人工精读**：审查者通读了全部 ~30 个安全核心源文件，作为最终裁决者复核高危项。
4. **真实服务器验证**：对生产 Rauthy 实例做只读协议探测，用真实数据验证 SDK 行为（不触碰任何破坏性端点）。

### 真实服务器验证到的事实（均与 SDK 行为对上）

| 事实 | 对 SDK 的意义 |
|------|--------------|
| `issuer` 带末尾斜杠 `https://your-rauthy.example.com/auth/v1/` | SDK 的"比较前去斜杠"归一化是**必需且正确**的 |
| 签名算法 = `RS256/RS384/RS512/EdDSA`，JWKS 同时发布 4 个密钥 | **RSA 验签路径（手写 PKCS#1 DER 编码器）是生产必经路径**，正确性关键；密钥均 ≥2048-bit |
| `code_challenge_methods_supported = [plain, S256]` | 服务器支持不安全的 `plain`，而 SDK **写死 S256** → 正确的抗降级 |
| 错误格式为非标准的 PascalCase `{timestamp,error,message}`（实测 `BadRequest`/`NotFound`/`Unauthorized`） | SDK 的三层降级错误解码器**已正确处理** |

---

## 3. 中危发现 / Medium Findings（须优先修复）

### 🟡 SEC-M01 ——「`userClaim`/`adminClaim` 配了但从未生效」（fail-open + 文档误导）

- **位置**：`RauthyConfig.swift:34-38`；`RauthyClient.swift` 的 `signIn` 全程
- **维度**：authz ｜ **核验**：needs_nuance（high → medium）
- **问题**：`config.userClaim`（"哪些用户能用此 app"）与 `adminClaim` 在全代码库中**只被赋值、从不被读取**。`signIn` 验完 token 后直接 `storage.save`，中间没有任何 `userClaim.matches(...)` 调用。结果：你的 Rauthy 认证过的**任何用户**都能进入 app。
- **加重项**：文档（`GettingStarted.md:51`、`RauthyConfig.swift:32-33` 注释）用现在时写"每个认证用户都必须满足此规则"，开发者会误以为有保护；`ClaimRules.md` 还引用了**根本不存在**的 `RauthySession/isUser`、`isAdmin` API。
- **为何 medium 非 high**：真正的安全边界在服务器（Rauthy 用自身 `ClaimMapping` 服务端鉴权），被放进来的用户拿不到服务器不授权的资源。这是**客户端便利性门禁失效 + 文档严重夸大**。
- **修复（采用方案 A：真正实现）**：新增 `RauthyError.notAuthorized`；在 `signIn` 的 `validateIDToken` 之后、`storage.save` 之前强制 `config.userClaim.matches(roles:groups:)`，不满足则抛 `.notAuthorized`。同步修文档：声明已强制、删除不存在的 API 引用、并**警告 `.group/.role` 规则需请求对应 `groups`/`roles` scope**，否则 token 无该 claim 会误拒（`.any` 为放行逃生口）。

### 🟡 SEC-M02 ——「`bootstrap()` 把服务端已吊销/已过期的本地 token 显示为已登录」（fail-open）

- **位置**：`SwiftUI/RauthyAuthState.swift:61-79, 169-174`
- **维度**：swiftui ｜ **核验**：needs_nuance（确认 medium）
- **问题**：启动时 `bootstrap()` 用 `try?` **吞掉 `fetchUser()` 的所有错误**，失败即回退到"用本地缓存 id_token 拼 User"，且**不检查 `exp` 过期、不区分"网络不通"与"服务器 401 踢出"**。链路：服务端吊销会话 → 本地 access token 尚未本地过期 → `/userinfo` 返回 401 → `reauthenticationRequired` 被 `try?` 吞掉 → 用旧 id_token 拼 User → `status = .signedIn` → 受保护界面被渲染，连客户端角色门禁也放行。
- **影响**：fail-open。服务器仍拒绝真实资源请求（401），所以是"鉴权瞥见(authorization glimpse)"而非 token 泄露，但 UI 会停在"已登录"假象。
- **修复**：让回退 fail-closed：`catch RauthyError.reauthenticationRequired` → `signOut(.local)` + `.signedOut`；仅 `catch .networkUnavailable` 才乐观回退本地 token；`userFromCurrentToken` 在 `token.isExpired()` 时返回 nil。

### 🟡 SEC-M03 ——「refresh 后不重新验证 id_token 签名/claims」（防御纵深）

- **位置**：`RauthyClient.swift:400-435`、`TokenExchange.swift:118-121`
- **维度**：protocol ｜ **核验**：确认 medium
- **问题**：登录时**会**完整验 id_token，但 **refresh 路径不验**——只用 `JWTDecoder.parseIDToken` 做结构性解析（不验签、不校验 claims）即存盘返回。违反 OIDC Core §3.1.3.7（验证不限于首次换码）。
- **影响**：信任模型下不可远程利用（需 TLS-MITM 或被攻陷 IdP），属防御纵深缺失；但读续期后 `sub`/`roles` 的代码在用未验证数据。
- **修复**：refresh 成功后，若有 id_token 则跑与登录一致的验证（验签 + claims，`nonce: nil`），验证通过再存盘。需把 `validateIDToken` 的 `nonce` 参数改为 `String?`。

### 🟡 SEC-M04 ——「`SecRandomCopyBytes` 返回值被丢弃，RNG 失败产生可预测密钥」（防御纵深）

- **位置**：`PKCE.swift:27`、`AuthorizationURLBuilder.swift:37`
- **维度**：crypto / apidesign / tests（三处报告，同一根因）｜ **核验**：needs_nuance（确认 medium）
- **问题**：两处生成随机数都写 `_ = SecRandomCopyBytes(...)`，**丢弃状态码**；缓冲区预填 0。若调用失败（返回非 `errSecSuccess`），将拿一段**全零**当随机数，生成固定可预测的 `code_verifier`/`state`/`nonce`——PKCE、CSRF、重放三道防线同时失效，且无报错。
- **为何 medium**：iOS/macOS 上走内核 CSPRNG 几乎不可能失败，现实触发概率≈0；但一旦触发后果灾难性，且**你自己的 `SessionStorage.swift` 对每个 `errSec*` 都严格检查了**，证明你知道正确写法，这两处只是漏了。
- **修复**：`guard SecRandomCopyBytes(...) == errSecSuccess else { preconditionFailure(...) }`（平台级不可恢复故障，trap 可接受）。两处都改。

### 🟡 SEC-M05 ——「核心验签管线 `validateIDToken` 端到端零测试」（回归风险）

- **位置**：`RauthyClient.swift:463-508`
- **维度**：tests ｜ **核验**：needs_nuance（high → medium）
- **问题**：子验证器单独都测得好，但把它们组装的 `validateIDToken`（kid 找 key → 找不到重拉一次 JWKS → 验签 → 校验 claims）**端到端无测试**，且它是 `private`、`signIn` 直接硬调 `WebAuthBridge`（无可注入接口），测试根本够不着。今日代码正确，但任何未来改动（调换验签与 claims 顺序、漏掉重拉）都会**通过全部 148 个测试**却放过伪造 token。
- **修复**：引入可测试接缝——把 `signIn` 回调后的逻辑抽成 `internal func completeSignIn(...)`，`validateIDToken` 改 `internal`；补测：kid 命中 / 未命中重拉一次成功 / 重拉仍失败→拒绝 / 验签先于 claims。

### 🟡 SEC-M06 ——「CSRF `state` 校验无回归测试」

- **位置**：`RauthyClient.swift:169-173`
- **维度**：tests ｜ **核验**：needs_nuance（确认 medium）
- **问题**：`returnedState != state` 这道 CSRF 防线**无测试**（同样因 `signIn` 不可注入而够不着）。custom-scheme 回调正是同设备恶意 app 可竞争的通道，这道校验是防御，却无回归测试。
- **修复**：同 SEC-M05 的接缝；补测：`state` 不匹配→抛 `stateMismatch` 且不换码；匹配→继续换码。

---

## 4. 低危发现 / Low Findings（建议修复）

> `SecRandomCopyBytes`（crypto/tests 维度的低危条目）已并入 SEC-M04。

| ID | 主题 | 位置 | 一句话 | 修复 |
|----|------|------|--------|------|
| SEC-L01 | 协议·多 aud 未要求 azp | `JWTClaimsValidator.swift:73-84` | OIDC §3.1.3.7 规则4：多受众应要求 `azp` | aud>1 且 azp 缺失则拒 |
| SEC-L02 | 协议·算法白名单顺序 | `RauthyClient.swift:485-507` | allowlist 在验签**之后**检查 | 验签前先 gate 算法 |
| SEC-L03 | 协议·JWKS 选 key 只看 kid | `JWK.swift:65-67` / 选 key 处 | 未过滤 `use=="sig"`、kty/alg 族 | 选 key 时加过滤 |
| SEC-L04 | 加密·RSA 无最小长度 | `RSAPublicKey.swift:22-46` | 不拒 <2048-bit 弱 RSA | 加 ≥2048 下限 |
| SEC-L05 | 授权·空 AND 放行所有人 | `ClaimRule.swift:37-38` | `.and([])` 因 allSatisfy 空集为真而 fail-open | 空 AND 返回 false |
| SEC-L06 | 授权·默认接受全 4 算法 | `RauthyConfig.swift:53` | 期望仅 EdDSA 仍接受 RS*；production 工厂无法收窄 | production 工厂加 `allowedAlgorithms` 参数 |
| SEC-L07 | 账户·passkey 名未编码 | `PasskeyAPI.swift:324-333` | 原始名拼进 URL，含空格会崩溃 | 百分号编码 name |
| SEC-L08 | 账户·multipart CRLF 注入 | `MultipartFormData.swift:30-36` | mimeType/filename 未转义拼进头部 | 拒含 CR/LF/引号的输入 |
| SEC-L09 | 账户·passkey 缺 mfa_mod_token_id | `PasskeyAPI.swift:296-333` | MFA 受保护账户的 passkey 管理可能不通 | 文档化限制（完整实现属新功能，留 TODO） |
| SEC-L10 | 账户·头像无大小/类型预校验 | `RauthyClient+Account.swift:180-207` | 上传前不校验大小/MIME | 加白名单 + 大小上限 |
| SEC-L11 | 存储·LocalDev 信任未按 host 限定 | `LocalDevURLSession.swift:55-78` | 自签 CA 对该 session 所有 host 生效 | 仅对 issuer host 应用 |
| SEC-L12 | 存储·shared session 磁盘缓存 | `RauthyClient.swift:61-66` | `/userinfo` 响应可能被缓存到磁盘 | 专建 `urlCache=nil` 的 session |
| SEC-L13 | SwiftUI·bootstrap 非幂等 | `RauthyAuthState.swift:61-79` | `.task` 可能重入并发跑多次 | 单飞合流 |
| SEC-L14 | SwiftUI·signIn 成功却发 .signedOut | `RauthyAuthState.swift:99-114` | token 已存好但 UI 显示登出 | 成功即保持 signedIn |
| SEC-L15 | SwiftUI·presentation context 进程级单例 | `RauthyPresentationContext.swift` | 多窗口"最后一个赢" | 文档化单窗口假设 |
| SEC-L16 | SwiftUI·lastError 不清理 | `RauthyAuthState.swift:87-122` | 重试成功后旧错误残留 | 入口清空 lastError |
| SEC-L17 | 日志·原始错误体进 .public 日志 | `RauthyClient.swift:277-280`、`RauthyClient+Account.swift:254-257` | `"\(error)"` 把服务器响应体写进 .public OSLog | 只记 statusCode/errorCode |
| SEC-L18 | 日志·完整响应体存进 message | `OAuthError.swift:104-107` | 兜底把整个 body 塞进 message 无上限 | 截断至 512B |
| SEC-L19 | 日志·OSLogHandler 硬编码 .public | `OSLogHandler.swift:70-82` | 抹掉 OSLog 默认动态内容脱敏 | 静态消息 public + metadata 值 private |
| SEC-L20 | API·默认 InMemoryStorage 与 README 不符 | `RauthyClient.swift:37` vs `README.md:102` | 默认内存存储，照抄快速开始会重启即丢登录 | README 传 `storage: .keychain()` |
| SEC-L21 | 文档·README 宣称的 .not 不存在 | `README.md` | 枚举只有 any/none/or/and | 删除 .not 表述 |
| SEC-L22 | 并发·JWKS 缓存重复重拉 | `RauthyClient.swift:453-477` | 并发验签良性缓存抖动（非数据竞争） | 可选：JWKS 取也单飞 |
| SEC-L23~L27 | 测试缺口 | 见各处 | azp 负例 / parseIDToken `none`,`HS256` / JWKSFetcher 错误路径 / Keychain 状态码映射 / RSA DER 负例 | 补测 |
| SEC-L28 | WebAuthBridge AnchorProvider 未强引用 | `WebAuthBridge.swift:32-49` | provider 仅被 weak 持有，可能被提前释放致登录偶发失败（与 PasskeyAPI 的自持有不一致） | 在 completion handler 中强引用 provider |

---

## 5. 信息项 / Informational

| ID | 位置 | 观察 | 处置 |
|----|------|------|------|
| SEC-I01 | `JWTClaimsValidator.swift:86-95` | `iat` 解码但从不校验，不拒"签发时间在未来" | 加未来 iat 校验（复用 .notYetValid） |
| SEC-I02 | `JWTClaimsValidator.swift:148-155` | EdDSA 的 at_hash 用 SHA-256（spec 模糊；Rauthy 不发 at_hash 故为死代码） | **保留**（SHA-256 符合 OIDC 家族惯例），加注释说明 |
| SEC-I03 | `RSAPublicKey.swift:129-148` | `readLength` 潜在 Int 溢出（仅测试路径） | 加 numBytes 上界保护 |
| SEC-I04 | `SessionStorage.swift:138-148` | macOS 未设 `kSecUseDataProtectionKeychain` | 设为 true（含 macOS 迁移注释） |
| SEC-I05 | `Browser.swift:42-71` | `openAccountURL` 转发未校验 path + 强解包 | 百分号编码 path、消除强解包 |
| SEC-I06 | `Account.swift:121-138` | 不可逆操作（删号/转 passkey-only）无 SDK 级二次确认 | **保留**（确认交 UI 层合理），文档说明 |
| SEC-I07 | `ClaimGate.swift:55-60` | `.and([])` 在动态构造时 match-all（SEC-L05 的重复视角） | 由 SEC-L05 统一修复 |

---

## 6. 被对抗性核验否决的误报 / Refuted

1. **"强制刷新会用到已轮换的旧 refresh token"** → 否。`refreshSession` 每次从 storage **重新读取**当前 token，拿到的是轮换后的新 token。
2. **"`Rauthy.locale` 全局变量是数据竞争"** → 否。它用 `OSAllocatedUnfairLock` **正确同步**，不是 race；发现自身结论即"这是优点"。
3. **"账户路径 `URL(string:)!` 强解包崩溃"** → 合并。崩溃角度被否（`sub` 是服务器控的 UUID），真正可操作的"passkey 名未编码"已作 SEC-L07 跟踪。

---

## 7. 做得好的地方 / What's Done Well

- **算法-密钥类型绑定**：`alg` 虽来自不可信 header，但验签强制 `kty` 匹配，加上 `SigningAlgorithm` 封闭枚举（`none`/HMAC 解码即失败）——**经典算法混淆攻击(alg-confusion)结构上不可能**。
- **issuer 双重锚定**：discovery 校验一次，token 校验时又钉死 `config.issuer`。
- **PKCE 写死 S256**：拒绝降级到服务器仍支持的不安全 `plain`。
- **单飞刷新**：actor + Task 句柄合流，防并发刷新风暴打爆轮换 token。
- **Keychain 属性** `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`：不进 iCloud、不离设备。
- **LocalDev 自签 CA 信任是"叠加"而非"替换"系统信任**，且仅 `localDev != nil` 时启用。
- **PasskeyAPI coordinator 用 `retainSelf` 自持有**，正确处理异步回调期间对象存活。
- **本地化用字面量 `%@` 替换而非 `String(format:)`**：翻译者打错占位符只会是显示瑕疵，不会崩溃。
- **Rauthy 非标准错误信封的三层降级解码**：真实服务器实测已正确命中。

---

## 8. 修复优先级 / Remediation Plan

- **第一批（行为正确性）**：SEC-M01、SEC-M02 —— 改变了你以为有、实际没有的保护。
- **第二批（防御纵深，小改动）**：SEC-M03、SEC-M04、SEC-L07、SEC-L08、SEC-L17。
- **第三批（测试网）**：SEC-M05/M06 接缝 + 验签管线/state 测试 + SEC-L23~L27。
- **第四批**：其余低危/信息项。

> **行为变更提醒**：SEC-M01 实施后，不满足 `userClaim` 的用户将无法登录。若你的 app 用了非 `.any` 的 `userClaim`，请确认已请求对应 `groups`/`roles` scope，否则用 `.any`。

---

## 附录 A：真实服务器 OIDC 元数据快照

- issuer: `https://your-rauthy.example.com/auth/v1/`（带末尾斜杠）
- 端点：authorize/token/userinfo/jwks(`/oidc/certs`)/revoke/end_session/device 齐全
- `id_token_signing_alg_values_supported`: `RS256, RS384, RS512, EdDSA`
- `code_challenge_methods_supported`: `plain, S256`
- `grant_types_supported`: 含 `password`(ROPC，SDK 正确地不使用)
- JWKS：4 个密钥（RS256/384/512 各一 RSA + 一 Ed25519），均带独立 `kid`，RSA ≥2048-bit
- 错误信封：PascalCase `{timestamp,error,message}`

---

## 附录 B：修复指南与修复记录

每条发现的**具体代码级修复方案**见配套文档 [`REMEDIATION.md`](REMEDIATION.md)。

> 状态：**全部 41 条发现已修复并验证（2026-06-16）**。`swift build` 通过；`swift test --no-parallel` = **173 tests / 46 suites 全过**（含新增的 SEC-* 回归套件）。经独立对抗性复审：**零回归、无任何安全检查被弱化**。

### 修复记录 / Changelog

- **范围**：24 个源/资源/文档文件（+294 −65 行），新增 **25 个回归测试**（8 个 `@Suite`，约 +728 行测试）。
- **6 中危全部落地**：
  - **M01** userClaim 在新抽出的 `completeSignIn` 中强制执行——不满足则抛 `RauthyError.notAuthorized` 且不存盘；
  - **M02** `bootstrap()` 改单飞 + **失效拦截**（401 → 登出清存储，仅 `networkUnavailable` 才回退本地**未过期** token）；
  - **M03** refresh 重验证 id_token（签名 + iss/aud/azp/exp）；
  - **M04** 两处 `SecRandomCopyBytes` 失败即 `preconditionFailure`；
  - **M05/M06** 抽出 `internal completeSignIn` + `internal validateIDToken` 测试接缝，并补端到端回归测试（含"kid miss 恰好重拉一次"断言 `jwksFetches==2`）。
- **M03 精修**：refresh 重验证**跳过 `requireVerifiedEmail`**——邮箱验证是**登录准入门禁**，不在每次静默续期重查（避免 Rauthy 若在 refresh id_token 省略 `email_verified` 时强制用户重登）。签名与其余 claims 仍照验。
- **28 低危 / 7 信息**：按 `REMEDIATION.md` 逐条落地。其中 **I02**（EdDSA at_hash 用 SHA-256）、**I06**（不可逆操作 SDK 层不二次确认）按报告判断**有意保留并文档说明**。
- **算法白名单**现于 `validateIDToken` **验签之前**执行（复审验证 `jwksFetches==0`）；**JWK 选 key**按 `use=="sig"` + kty/crv 算法族过滤（复审确认不会误拒 Rauthy 真实的 RS256/384/512 与 Ed25519 密钥）。

### ⚠️ 行为变更（部署前确认）

- **M01**：实施后，不满足 `userClaim` 的用户将被拒登录（抛 `.notAuthorized`）。`.any` 为"放行所有人"逃生口；`.group/.role` 规则需请求对应 `groups`/`roles` scope，否则 token 无该 claim 会误拒。
- **M03/SEC-L12/I04**：refresh 重验证、生产环境改用无缓存 URLSession、macOS 启用 data-protection keychain——均为更严格/更安全方向；macOS 上改动前已存的旧 keychain 条目会读不到一次（经刷新/重登恢复，无数据丢失）。
