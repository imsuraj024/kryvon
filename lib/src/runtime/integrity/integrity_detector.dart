import 'package:kryvon/src/runtime/channels/runtime_channel.dart';
import 'integrity_detection_result.dart';

/// Dart-side bridge for native app integrity detection.
///
/// Passes [expectedSignatureSha256] to the native layer so that certificate
/// comparison happens natively, reducing exposure of the expected value in
/// Dart bytecode.
class IntegrityDetector {
  const IntegrityDetector();

  Future<IntegrityDetectionResult> check({
    String? expectedSignatureSha256,
  }) async {
    final response = await RuntimeChannel.checkIntegrity(
      expectedSignatureSha256: expectedSignatureSha256,
    );

    if (response['__compromised'] == true) {
      return const IntegrityDetectionResult(
        integrityOk: false,
        indicators: ['channelCompromised'],
      );
    }

    final raw = response['indicators'];
    final indicators = raw is List
        ? raw.map((e) => e.toString()).toList()
        : <String>[];

    final liveSha256 = response['signature'] as String?;

    return IntegrityDetectionResult(
      integrityOk: indicators.isEmpty,
      indicators: indicators,
      liveSha256: liveSha256,
    );
  }
}
