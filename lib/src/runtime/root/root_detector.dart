import 'root_detection_result.dart';
import 'root_indicator.dart';
import '../channels/runtime_channel.dart';

/// Bridges Dart to the native root-detection logic via [RuntimeChannel].
///
/// The actual detection is performed in Kotlin (`RootDetector.kt`). This class
/// deserialises the platform response into a [RootDetectionResult].
class RootDetector {
  const RootDetector();

  /// Queries the native layer and returns the [RootDetectionResult].
  Future<RootDetectionResult> check() async {
    final response = await RuntimeChannel.checkRoot();

    final List<dynamic> rawIndicators =
        response['indicators'] as List<dynamic>;

    final indicators = rawIndicators
    .map((e) => RootIndicatorType.values.firstWhere(
          (type) => type.name == e,
        ))
    .toList();

    return RootDetectionResult(
      isRooted: indicators.isNotEmpty,
      indicators: indicators,
    );
  }
}