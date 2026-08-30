import 'kryvon_enums.dart';

class Evidence {
  const Evidence({
    required this.signal,
    required this.status,
    required this.confidence,
    required this.source,
    required this.platform,
    required this.observedAt,
    this.metadata = const <String, Object?>{},
  });

  final String signal;
  final EvidenceStatus status;
  final Confidence? confidence;
  final String source;
  final String platform;
  final DateTime observedAt;
  final Map<String, Object?> metadata;
}
