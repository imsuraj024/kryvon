import 'evidence.dart';
import 'kryvon_enums.dart';

/// A snapshot of signal coverage for one assessment pass.
///
/// This is a contract for future collectors, not a detector implementation.
/// A pass is complete only when every expected signal has exactly one outcome
/// and every outcome is either detected or notDetected. Unknown, failed, and
/// unsupported outcomes remain explicit gaps in coverage.
class SignalRun {
  SignalRun({
    required List<String> expectedSignals,
    required List<Evidence> outcomes,
  })  : expectedSignals = List<String>.unmodifiable(expectedSignals),
        outcomes = List<Evidence>.unmodifiable(outcomes);

  final List<String> expectedSignals;
  final List<Evidence> outcomes;

  bool get hasUniqueExpectedSignals =>
      expectedSignals.isNotEmpty && expectedSignals.toSet().length == expectedSignals.length;

  bool get isComplete {
    if (!hasUniqueExpectedSignals) return false;
    final expected = expectedSignals.toSet();
    final bySignal = <String, List<Evidence>>{};
    for (final outcome in outcomes) {
      if (!expected.contains(outcome.signal)) return false;
      bySignal.putIfAbsent(outcome.signal, () => <Evidence>[]).add(outcome);
    }
    if (bySignal.length != expected.length) return false;
    for (final signal in expected) {
      final matching = bySignal[signal];
      if (matching == null || matching.length != 1) return false;
      final status = matching.single.status;
      if (status != EvidenceStatus.detected && status != EvidenceStatus.notDetected) {
        return false;
      }
    }
    return true;
  }

  bool get allNotDetected =>
      isComplete && outcomes.every((outcome) => outcome.status == EvidenceStatus.notDetected);

  List<String> get uncertainties {
    final expected = expectedSignals.toSet();
    final seen = <String, int>{};
    final issues = <String>[];
    for (final outcome in outcomes) {
      if (!expected.contains(outcome.signal)) {
        issues.add('Unexpected outcome for signal "${outcome.signal}".');
        continue;
      }
      seen.update(outcome.signal, (count) => count + 1, ifAbsent: () => 1);
      if (outcome.status == EvidenceStatus.failed) {
        issues.add('Signal "${outcome.signal}" failed.');
      } else if (outcome.status == EvidenceStatus.unsupported) {
        issues.add('Signal "${outcome.signal}" is unsupported on this platform.');
      } else if (outcome.status == EvidenceStatus.unknown) {
        issues.add('Signal "${outcome.signal}" returned an unknown outcome.');
      }
    }
    for (final signal in expectedSignals) {
      final count = seen[signal] ?? 0;
      if (count == 0) issues.add('Signal "$signal" has no outcome.');
      if (count > 1) issues.add('Signal "$signal" has multiple outcomes.');
    }
    if (!hasUniqueExpectedSignals) {
      issues.add('Expected signal identifiers must be non-empty and unique.');
    }
    return List<String>.unmodifiable(issues);
  }
}
