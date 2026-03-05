import 'package:kryvon/src/runtime/root/root_indicator.dart';

/// Holds the raw output of a root-detection scan.
///
/// Produced by [RootDetector.check] and consumed by [RootGuard].
class RootDetectionResult {
  /// Whether the device shows any sign of being rooted.
  final bool isRooted;

  /// The individual signals that contributed to the [isRooted] determination.
  final List<RootIndicatorType> indicators;

  const RootDetectionResult({
    required this.isRooted,
    required this.indicators,
  });
}