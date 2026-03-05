import 'threat_type.dart';
import 'severity.dart';

/// Represents a single security threat detected by a [Guard].
///
/// Individual events are passed to [KryvonPolicy.onThreat] as they are
/// produced. After all guards finish, a synthetic [ThreatType.deviceCompromised]
/// event is created from the aggregated risk score.
class ThreatEvent {
  /// The category of threat that was detected.
  final ThreatType type;

  /// How severe this particular threat instance is.
  final ThreatSeverity severity;

  /// Optional guard-specific details (e.g. indicator names, signal values).
  final Map<String, dynamic>? metadata;

  const ThreatEvent({
    required this.type,
    required this.severity,
    this.metadata,
  });
}