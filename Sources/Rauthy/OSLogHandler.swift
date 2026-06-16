#if canImport(os)
import Foundation
import Logging
import os

/// A `swift-log` `LogHandler` that forwards to Apple's unified logging
/// system (`os.Logger`), making SDK diagnostics visible in Console.app and
/// the Xcode console.
///
/// Call ``bootstrap(subsystem:)`` once at app launch — typically in your
/// `@main` App's `init()`:
///
/// ```swift
/// @main
/// struct MyApp: App {
///     init() {
///         RauthyOSLogHandler.bootstrap()
///     }
///     // ...
/// }
/// ```
///
/// After bootstrap, every `Logger` created via `swift-log` (including the
/// default one in `RauthyConfig`) flows to OSLog.
///
/// **Privacy:** Metadata values are marked `.public` so they appear in
/// Console.app outside of Xcode. The SDK's internal log messages never
/// include token strings or other secrets. If you add your own logging
/// via `config.logger.info("...")` and include a secret in metadata, it
/// WILL be visible in Console.app — wrap it in `[REDACTED]` yourself or
/// use a custom handler.
public struct RauthyOSLogHandler: LogHandler {
    private let label: String
    private let logger: os.Logger

    public var metadata: Logging.Logger.Metadata = [:]
    public var logLevel: Logging.Logger.Level = .info

    public init(label: String, subsystem: String = "rauthy.swift") {
        self.label = label
        self.logger = os.Logger(subsystem: subsystem, category: label)
    }

    public subscript(metadataKey key: String) -> Logging.Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    public func log(
        level: Logging.Logger.Level,
        message: Logging.Logger.Message,
        metadata explicit: Logging.Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        let merged = self.metadata.merging(explicit ?? [:]) { _, new in new }
        let metaString: String
        if merged.isEmpty {
            metaString = ""
        } else {
            let pairs = merged
                .sorted { $0.key < $1.key }
                .map { "\($0.key)=\($0.value)" }
                .joined(separator: " ")
            metaString = " " + pairs
        }

        // The static message text is safe to log publicly; dynamic metadata
        // values may carry identifiers (sub, kid, error details), so mark them
        // `.private` so OSLog redacts them as <private> in Console.app on
        // shipped builds unless the device is configured to reveal them.
        let msg = "\(message)"
        switch level {
        case .trace, .debug:
            logger.debug("\(msg, privacy: .public)\(metaString, privacy: .private)")
        case .info, .notice:
            logger.info("\(msg, privacy: .public)\(metaString, privacy: .private)")
        case .warning:
            logger.warning("\(msg, privacy: .public)\(metaString, privacy: .private)")
        case .error:
            logger.error("\(msg, privacy: .public)\(metaString, privacy: .private)")
        case .critical:
            logger.fault("\(msg, privacy: .public)\(metaString, privacy: .private)")
        }
    }

    /// Configure `swift-log`'s global logging system to send everything
    /// through `RauthyOSLogHandler`. Call once at app launch.
    ///
    /// `LoggingSystem.bootstrap` may be called only once per process —
    /// if your app already bootstrapped a different handler, don't call
    /// this. To layer multiple handlers, use `MultiplexLogHandler` from
    /// swift-log directly.
    public static func bootstrap(subsystem: String = "rauthy.swift") {
        LoggingSystem.bootstrap { label in
            RauthyOSLogHandler(label: label, subsystem: subsystem)
        }
    }
}
#endif
