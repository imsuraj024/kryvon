import 'package:kryvon/src/runtime/root/root_indicator.dart';

class RootDetectionResult {
  final bool isRooted;
  final List<RootIndicatorType> indicators;

  const RootDetectionResult({
    required this.isRooted,
    required this.indicators,
  });
}