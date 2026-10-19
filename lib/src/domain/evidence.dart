import 'kryvon_enums.dart';

/// A single observation made by a signal source.
///
/// [confidence] may be null when the source cannot provide a meaningful
/// confidence estimate (for example, when the observation failed).
class Evidence {
  Evidence({
    required this.signal,
    required this.status,
    required this.confidence,
    required this.source,
    required this.platform,
    required this.observedAt,
    Map<String, Object?> metadata = const <String, Object?>{},
  }) : metadata = Map<String, Object?>.unmodifiable(metadata);

  final String signal;
  final EvidenceStatus status;
  final Confidence? confidence;
  final String source;
  final String platform;
  final DateTime observedAt;

  /// Diagnostic metadata. Callers cannot mutate the map after construction.
  final Map<String, Object?> metadata;
}
