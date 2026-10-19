import '../domain/evidence.dart';
import '../domain/kryvon_enums.dart';

class DetectorRequest {
  DetectorRequest({
    required this.requestId,
    required this.signalId,
    required this.context,
    required this.platform,
    Map<String, Object?> configuration = const <String, Object?>{},
  }) : configuration = Map<String, Object?>.unmodifiable(configuration);

  final String requestId;
  final String signalId;
  final AssessmentContext context;
  final String platform;
  final Map<String, Object?> configuration;
}

abstract interface class SignalDetector {
  String get id;
  List<String> get signalIds;
  Future<Evidence> evaluate(DetectorRequest request);
}

class DetectorRegistry {
  DetectorRegistry(List<SignalDetector> detectors)
      : detectors = List<SignalDetector>.unmodifiable(detectors) {
    final detectorIds = <String>{};
    final signalOwners = <String, String>{};
    for (final detector in this.detectors) {
      final id = detector.id.trim();
      if (id.isEmpty) throw ArgumentError.value(detector.id, 'detector.id', 'Detector IDs must not be empty.');
      if (!detectorIds.add(id)) throw ArgumentError.value(detector.id, 'detectors', 'Detector IDs must be unique.');
      if (detector.signalIds.isEmpty) throw ArgumentError.value(detector.signalIds, 'detector.signalIds', 'A detector must own at least one signal.');
      final localSignals = <String>{};
      for (final signalId in detector.signalIds) {
        final normalized = signalId.trim();
        if (normalized.isEmpty) throw ArgumentError.value(signalId, 'detector.signalIds', 'Signal IDs must not be empty.');
        if (!localSignals.add(normalized)) throw ArgumentError.value(signalId, 'detector.signalIds', 'Signal IDs must be unique within a detector.');
        final owner = signalOwners[normalized];
        if (owner != null) throw ArgumentError.value(signalId, 'detectors', 'Signal "$normalized" is owned by both "$owner" and "$id".');
        signalOwners[normalized] = id;
      }
    }
  }

  final List<SignalDetector> detectors;

  List<String> get expectedSignals => List<String>.unmodifiable(
        detectors.expand((detector) => detector.signalIds.map((signal) => signal.trim())),
      );

  SignalDetector? ownerOf(String signalId) {
    final normalized = signalId.trim();
    for (final detector in detectors) {
      if (detector.signalIds.any((signal) => signal.trim() == normalized)) return detector;
    }
    return null;
  }
}
