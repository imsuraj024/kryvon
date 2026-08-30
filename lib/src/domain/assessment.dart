import 'evidence.dart';
import 'kryvon_enums.dart';

class Assessment {
  const Assessment({
    required this.id,
    required this.threat,
    required this.severity,
    required this.confidence,
    required this.supportingEvidence,
    required this.reason,
  });

  final String id;
  final String threat;
  final Severity severity;
  final Confidence confidence;
  final List<Evidence> supportingEvidence;
  final String reason;
}
