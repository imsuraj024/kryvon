/// Result produced by [HookDetector] after querying the native runtime.
class HookDetectionResult {
  /// `true` when at least one hooking-framework indicator was found.
  final bool hookDetected;

  /// Names of the individual indicators that were triggered.
  ///
  /// Possible values: `fridaProcess`, `fridaPort`, `fridaLibrary`,
  /// `xposedBridge`, `xposedModules`.
  final List<String> indicators;

  const HookDetectionResult({
    required this.hookDetected,
    required this.indicators,
  });
}
