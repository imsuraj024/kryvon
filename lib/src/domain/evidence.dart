import 'kryvon_enums.dart';

/// A single observation made by a signal source.
/// [confidence] may be null when the source cannot provide a meaningful
/// confidence estimate, for example when the observation failed.
class Evidence {
  Evidence({
    required this.signal,
    required this.status,
    required this.confidence,
    required this.source,
    required this.platform,
    required this.observedAt,
    Map<String, Object?> metadata = const <String, Object?>{},
  }) : metadata = Map<String, Object?>.unmodifiable(
          metadata.map((key, value) => MapEntry(key, _freezeMetadataValue(value))),
        );

  final String signal;
  final EvidenceStatus status;
  final Confidence? confidence;
  final String source;
  final String platform;
  final DateTime observedAt;

  /// A recursively frozen snapshot of diagnostic metadata.
  final Map<String, Object?> metadata;
}

Object? _freezeMetadataValue(Object? value) {
  if (value is Map) {
    return Map<Object?, Object?>.unmodifiable(
      value.map((key, nested) => MapEntry(key, _freezeMetadataValue(nested))),
    );
  }
  if (value is List) {
    return List<Object?>.unmodifiable(value.map(_freezeMetadataValue));
  }
  if (value is Set) {
    return Set<Object?>.unmodifiable(value.map(_freezeMetadataValue));
  }
  return value;
}
