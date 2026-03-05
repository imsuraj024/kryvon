/// Controls the verbosity of Kryvon's internal logger.
///
/// Pass the desired level to [Kryvon.initialize] via its `logLevel` parameter.
/// Only messages at or above the configured level are emitted.
enum LogLevel {
  /// Verbose output, including internal guard lifecycle events.
  debug,

  /// General operational messages (default).
  info,

  /// Potential problems that do not stop execution.
  warning,

  /// Errors that indicate a failure in a guard or the runtime.
  error,

  /// No log output whatsoever.
  silent,
}