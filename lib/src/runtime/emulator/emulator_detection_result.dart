/// Result produced by [EmulatorDetector] after querying the native runtime.
class EmulatorDetectionResult {
  /// `true` when at least one emulator indicator was found.
  final bool emulatorDetected;

  /// Names of the individual indicators that were triggered.
  ///
  /// Possible values: `genericFingerprint`, `qemuProps`, `emulatorBuildProps`,
  /// `emulatorFiles`, `genymotion`.
  final List<String> indicators;

  const EmulatorDetectionResult({
    required this.emulatorDetected,
    required this.indicators,
  });
}
