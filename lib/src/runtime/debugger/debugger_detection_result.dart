class DebuggerDetectionResult {

  final List<String> indicators;

  const DebuggerDetectionResult({
    required this.indicators,
  });

  bool get debuggerDetected => indicators.isNotEmpty;

}