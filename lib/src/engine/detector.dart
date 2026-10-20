import '../domain/evidence.dart';
import '../domain/kryvon_enums.dart';

class DetectorRequest {
  DetectorRequest({
    required this.requestId,
    required this.signalId,
    required this.context,
    required this.platform,
    Map<String, Object?> configuration = const <String, Object?>{},
  }) : configuration = _freezeConfiguration(configuration);

  final String requestId;
  final String signalId;
  final AssessmentContext context;
  final String platform;

  /// An immutable snapshot so detectors cannot mutate shared run configuration.
  final Map<String, Object?> configuration;
}

/// A detector may be invoked concurrently for different signals and from
/// overlapping runs. Implementations must be re-entrant/concurrency-safe, or
/// provide their own serialization and request/response correlation.
abstract interface class SignalDetector {
  String get id;
  List<String> get signalIds;
  Future<Evidence> evaluate(DetectorRequest request);
}

/// A validated snapshot of a detector's identity and owned signals.
class DetectorRegistration {
  DetectorRegistration({
    required this.detector,
    required this.id,
    required List<String> signalIds,
  }) : signalIds = List<String>.unmodifiable(signalIds);

  final SignalDetector detector;
  final String id;
  final List<String> signalIds;
}

class DetectorRegistry {
  DetectorRegistry(List<SignalDetector> detectors)
    : registrations = _validateAndSnapshot(detectors),
      detectors = List<SignalDetector>.unmodifiable(detectors);

  /// Validated registrations in deterministic execution order.
  final List<DetectorRegistration> registrations;

  /// Detector instances in registration order.
  final List<SignalDetector> detectors;

  List<String> get expectedSignals => List<String>.unmodifiable(
    registrations.expand((registration) => registration.signalIds),
  );

  SignalDetector? ownerOf(String signalId) {
    final normalized = signalId.trim();
    for (final registration in registrations) {
      if (registration.signalIds.contains(normalized)) {
        return registration.detector;
      }
    }
    return null;
  }

  static List<DetectorRegistration> _validateAndSnapshot(
    List<SignalDetector> detectors,
  ) {
    final detectorIds = <String>{};
    final signalOwners = <String, String>{};
    final registrations = <DetectorRegistration>[];

    for (final detector in detectors) {
      final rawId = detector.id;
      final id = rawId.trim();
      if (id.isEmpty) {
        throw ArgumentError.value(
          rawId,
          'detector.id',
          'Detector IDs must not be empty.',
        );
      }
      if (!detectorIds.add(id)) {
        throw ArgumentError.value(
          rawId,
          'detectors',
          'Detector IDs must be unique.',
        );
      }

      final signalIds = detector.signalIds
          .map((signalId) => signalId.trim())
          .toList(growable: false);
      if (signalIds.isEmpty) {
        throw ArgumentError.value(
          signalIds,
          'detector.signalIds',
          'A detector must own at least one signal.',
        );
      }

      final localSignals = <String>{};
      for (final signalId in signalIds) {
        if (signalId.isEmpty) {
          throw ArgumentError.value(
            signalId,
            'detector.signalIds',
            'Signal IDs must not be empty.',
          );
        }
        if (!localSignals.add(signalId)) {
          throw ArgumentError.value(
            signalId,
            'detector.signalIds',
            'Signal IDs must be unique within a detector.',
          );
        }
        final owner = signalOwners[signalId];
        if (owner != null) {
          throw ArgumentError.value(
            signalId,
            'detectors',
            'Signal "$signalId" is owned by both "$owner" and "$id".',
          );
        }
        signalOwners[signalId] = id;
      }

      registrations.add(
        DetectorRegistration(detector: detector, id: id, signalIds: signalIds),
      );
    }

    return List<DetectorRegistration>.unmodifiable(registrations);
  }
}

Map<String, Object?> _freezeConfiguration(Map<String, Object?> values) =>
    Map<String, Object?>.unmodifiable(
      values.map(
        (key, value) => MapEntry(key, _freezeConfigurationValue(value)),
      ),
    );

Object? _freezeConfigurationValue(Object? value) {
  if (value is Map) {
    return Map<Object?, Object?>.unmodifiable(
      value.map(
        (key, nested) => MapEntry(key, _freezeConfigurationValue(nested)),
      ),
    );
  }
  if (value is List) {
    return List<Object?>.unmodifiable(value.map(_freezeConfigurationValue));
  }
  if (value is Set) {
    return Set<Object?>.unmodifiable(value.map(_freezeConfigurationValue));
  }
  return value;
}
