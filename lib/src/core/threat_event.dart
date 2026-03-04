import 'threat_type.dart';
import 'severity.dart';

class ThreatEvent {
  final ThreatType type;
  final ThreatSeverity severity;
  final Map<String, dynamic>? metadata;

  const ThreatEvent({
    required this.type,
    required this.severity,
    this.metadata,
  });
}