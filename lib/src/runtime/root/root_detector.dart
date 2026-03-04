import 'root_detection_result.dart';
import 'root_indicator.dart';
import '../channels/runtime_channel.dart';

class RootDetector {
  const RootDetector();

  Future<RootDetectionResult> check() async {
    print("Calling native root detection...");
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