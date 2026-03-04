import 'package:kryvon/src/core/enforcement_strategy.dart';

import 'threat_event.dart';
import 'severity.dart';

typedef ThreatHandler = void Function(ThreatEvent event);

class KryvonPolicy {
  final ThreatSeverity blockThreshold;
  final EnforcementStrategy enforcementStrategy;
  final ThreatHandler? onThreat;

  const KryvonPolicy({
    this.blockThreshold = ThreatSeverity.high,
    this.enforcementStrategy = EnforcementStrategy.emitOnly,
    this.onThreat,
  });

  bool shouldBlock(ThreatEvent event) {
    return event.severity.index >= blockThreshold.index;
  }

  factory KryvonPolicy.fintech() {
    return const KryvonPolicy(
      blockThreshold: ThreatSeverity.medium,
      enforcementStrategy: EnforcementStrategy.terminateApp,
    );
  }
}