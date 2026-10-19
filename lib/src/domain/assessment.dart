import 'evidence.dart';
import 'kryvon_enums.dart';

/// An interpretation of evidence, expressed independently of enforcement.
class Assessment {
  Assessment({
    required this.id,
    required this.threat,
    required this.severity,
    required this.confidence,
    required List<Evidence> supportingEvidence,
    required this.reason,
    this.correlationKey,
  }) : supportingEvidence = List<Evidence>.unmodifiable(supportingEvidence);

  final String id;
  final String threat;
  final Severity severity;
  final Confidence confidence;
  final List<Evidence> supportingEvidence;
  final String reason;

  /// Stable identifier for assessments that describe the same underlying
  /// condition. Null means the engine must not assume correlation.
  final String? correlationKey;
}
