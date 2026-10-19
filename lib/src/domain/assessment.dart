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
  }) : supportingEvidence = List<Evidence>.unmodifiable(supportingEvidence);

  final String id;
  final String threat;
  final Severity severity;
  final Confidence confidence;
  final List<Evidence> supportingEvidence;
  final String reason;
}
