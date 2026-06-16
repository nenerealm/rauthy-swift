# Rauthy Swift SDK

[Rauthy](https://github.com/sebadob/rauthy) 的 Swift 客户端 SDK。Rauthy 是基于
Rust 实现的开源 OIDC/OAuth2 身份服务。本 SDK 以 SwiftUI 为先,Swift 6 严格并发,
不依赖任何第三方加密库。

[![CI](https://github.com/nenerealm/rauthy-swift/actions/workflows/test.yml/badge.svg)](https://github.com/nenerealm/rauthy-swift/actions/workflows/test.yml)
[![Swift 6](https://img.shields.io/badge/Swift-6.0+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2016+%20|%20macOS%2013+%20|%20tvOS%2016+%20|%20visionOS%201+-blue.svg)](#平台支持)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**状态:v1.0 GA。** 已对真实 Rauthy 服务器做完整端到端验证,130 个测试,
经过多轮对抗审查,Swift 6 并发干净。

## 平台支持

- iOS 16+
- macOS 13+
- tvOS 16+
- visionOS 1+
- watchOS 不支持(watchOS 没有 `ASWebAuthenticationSession`)

只支持 SwiftUI,不支持 UIKit。

## 安装

使用 Swift Package Manager。在你的 `Package.swift` 里:

```swift
dependencies: [
    .package(url: "https://github.com/nenerealm/rauthy-swift", from: "1.0.0"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "Rauthy", package: "rauthy-swift"),
        ]
    )
]
```

或者在 Xcode 里:**File → Add Package Dependencies → 粘贴仓库 URL**。

## v1.0 含哪些东西

- **完整的 PKCE 登录流程**,通过 `ASWebAuthenticationSession` 实现(RFC 7636)
- **Token 续期** —— `validAccessToken()` 自动续,也可显式调
  `refreshSession()`。单飞合流,防止并发刷新风暴
- **Token 吊销**(RFC 7009),通过 `signOut(scope: .revokeTokens)`
- **RP-Initiated Logout**(OIDC 1.0),通过 `signOut(scope: .rpInitiated)` /
  `.full`
- **ID token 签名校验** —— Ed25519(走 CryptoKit)+ RSA RS256/384/512
  (走 Security framework,自带 PKCS#1 DER 编码器)
- **ID token claim 校验** —— iss / aud / azp / exp / nbf / nonce / at_hash /
  email_verified
- **OIDC discovery + JWKS 拉取**,kid miss 时单次重拉;discovery `issuer`
  字段对齐配置 issuer 才接受(防止恶意/错配 IdP)
- **Keychain 持久化**(`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`)+
  内存版本(供测试用)
- **`Browser.openAccountDashboard`** —— 把用户跳到 Rauthy 的 web 账户面板,
  在那里管理个人资料 / 密码 / passkey / 设备 / 注销账户等 SDK 不暴露的功能
- **SwiftUI 原语** —— `RauthyAuthState`、`RauthyAuthGate`、
  `.rauthyPresentationContext()`、`@RauthyUser`、`.rauthyRequiresClaim` /
  `.rauthyRequiresRole` / `.rauthyRequiresGroup`、`.rauthyErrorAlert(_:)`
- **`ClaimRule`** —— 声明式授权规则(`.role`、`.group`,组合子 `.and` /
  `.or` / `.not`)
- **本地化错误消息** —— 英语 / 简体中文 / 日语,运行时可通过 `Rauthy.locale`
  切换。格式化字符串安全(翻译者打错 `%@` 占位符不会让错误路径崩溃)
- **`swift-log` 集成** —— 自带 `RauthyOSLogHandler` 直接对接 OSLog
- **Swift 6 严格并发模式**(`StrictConcurrency=complete`)
- **DocC 文档** —— 入门指南、claim 规则、SwiftUI 集成、本地化
- **130 个测试,跨 33 个 suite** —— 单元、wire 协议、单飞 refresh、多语言
  切换、签名校验

## v1.0 故意不含的东西

- **DPoP token binding**(RFC 9449)—— 推迟到 v1.1。设计已完成,卡在
  Rauthy 上游对 ES256 签名的支持上
- **多账户** —— 推迟到 v1.5。单账户已经覆盖了绝大多数场景
- **Passkey 作为登录方式** —— Rauthy 的 web 登录页已经通过 OAuth code flow
  redirect 处理了 passkey 认证,SDK 不需要并行再实现一遍
- **原生账户自助服务 / Passkey 管理 API** —— Rauthy 的 `PrincipalMiddleware`
  对 `/users/{id}/self*` 只接受 session cookie 或 API-key,拒绝原生 OIDC
  Bearer,所以 SDK 不封装个人资料 / 偏好用户名 / 设备 / 头像 / passkey / 注销
  账户的增删改;改用 `Browser.openAccountDashboard` 跳转 Rauthy 的 web 账户面板
- **`/users/request_reset`**(忘记密码)—— 需要服务端 PoW solver,这属于
  Rauthy web UI 的范畴,不应该出现在面向已登录用户的 SDK 里
- **邮件确认端点** —— 用户点邮件里的链接,服务端处理一切,不需要 SDK 调用
- **UIKit 支持** —— 明确不在范围内,只支持 SwiftUI
- **CocoaPods / XCFramework 发布** —— 只支持 SwiftPM。本地化资源包依赖
  SwiftPM 的 `Bundle.module`

## 快速开始

```swift
import Rauthy
import SwiftUI

@main
struct MyApp: App {
    let rauthy = RauthyClient(config: .production(
        issuer: URL(string: "https://your-rauthy.example.com/auth/v1")!,
        clientID: "my-app",
        redirectURI: URL(string: "myapp://callback")!,
        userClaim: .or([.group("users")]),
        adminClaim: .or([.role("admin")])
    ))

    @StateObject var auth: RauthyAuthState

    init() {
        let client = rauthy
        _auth = StateObject(wrappedValue: RauthyAuthState(client: client))

        // 可选:本地化错误消息
        Rauthy.locale = Locale(identifier: "zh-Hans")
    }

    var body: some Scene {
        WindowGroup {
            RauthyAuthGate { user in
                MainView(user: user)
            } signedOut: {
                LoginView()
            }
            .environmentObject(auth)
            .rauthyPresentationContext()
            .rauthyErrorAlert(auth)
            .task { await auth.bootstrap() }
        }
    }
}

struct LoginView: View {
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        Button("登录") {
            Task { await auth.signIn() }
        }
        .disabled(auth.isBusy)
    }
}

struct MainView: View {
    let user: User
    @EnvironmentObject var auth: RauthyAuthState

    var body: some View {
        VStack {
            Text("你好,\(user.email ?? "匿名用户")")

            // 声明式授权 —— 只有 admin 才能看到
            AdminPanel()
                .rauthyRequiresRole("admin")
        }
        .toolbar {
            Button("登出") {
                Task { await auth.signOut() }
            }
        }
    }
}
```

## 试试 sample app

`Samples/NotesApp/` 下有一个 SwiftUI iOS app(三个 tab),演示了登录、用户信息、
claim 门控、跳转 Rauthy 的 web 账户面板、以及四种 `signOut` 模式。

```bash
cd Samples/NotesApp
brew install xcodegen     # 仅需一次
xcodegen generate
open NotesApp.xcodeproj
```

修改 `NotesApp/Config.swift` 指向你自己的 Rauthy 服务器。完整的搭建说明
(admin client 注册、手动 Xcode 路径等)见
[`Samples/NotesApp/SETUP.md`](Samples/NotesApp/SETUP.md)。

## 构建和测试

```bash
swift build
swift test --no-parallel    # 必须串行:Rauthy.locale 是进程级全局变量
```

需要 Swift 6.0+(在 Swift 6.3 / Xcode 16+ 上测过)。

生成 DocC 文档:

```bash
swift package generate-documentation --target Rauthy
```

## 本地化

默认跟随系统 locale。运行时覆盖:

```swift
Rauthy.locale = Locale(identifier: "zh-Hans")
// 也可以传 "ja",或者传 nil 跟随系统

catch let err as RauthyError {
    showAlert(err.localizedDescription)  // 网络不可用,请检查网络连接后重试。
}
```

已自带 `en` / `zh-Hans` / `ja` 三个语言。其它 locale 自动回退到英文。欢迎
PR 加新翻译 —— 看 `Sources/Rauthy/Resources/<lang>.lproj/Localizable.strings`。

## 路线图

| 里程碑 | 状态 | 重点 |
|--------|------|------|
| v1.0 | ✅ 已发 | PKCE + Token 刷新/吊销 + ID token 校验 + SwiftUI 原语 + i18n |
| v1.1 | 计划中 | DPoP token binding(RFC 9449)—— 等 Rauthy 上游 ES256 |
| v1.5 | 计划中 | 多账户支持 |
| v2.0 | 远期 | Secure Enclave 私钥存储;重新评估 XCFramework 发布 |

## 许可证

[Apache 2.0](LICENSE) —— 与 Rauthy 保持一致。

## 贡献

欢迎通过 GitHub Issues 和 Discussions 提 bug 报告、提问、贡献翻译。非小型
功能开发请先开 Discussion 对齐范围。

上游 Rauthy 项目在 https://github.com/sebadob/rauthy ——
任何客户端-服务端协议相关的问题请去那边协调。

## 致谢

构建于 Sebastian Dobe 等贡献者维护的 Rauthy 之上。本 SDK 是非官方、由社区
维护的客户端,目前未获 Rauthy 项目正式背书(如果维护方愿意,我们乐于协调)。
