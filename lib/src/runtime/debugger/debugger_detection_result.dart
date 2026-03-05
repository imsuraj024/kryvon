/// Holds the raw output of a debugger-detection scan.
///
/// Produced by [DebuggerDetector.check] and consumed by [DebuggerGuard].
class DebuggerDetectionResult {
  /// The native signal names that were active at the time of the scan.
  ///
  /// Known values: `tracerPid`, `androidDebugger`, `systemDebuggable`,
  /// `jdwpEnabled`, `debuggableApp`.
  final List<String> indicators;

  const DebuggerDetectionResult({
    required this.indicators,
  });

  /// `true` when at least one debugger signal was detected.
  bool get debuggerDetected => indicators.isNotEmpty;
}