import '../domain/kryvon_enums.dart';
import 'assessment_generator.dart';

/// First explicit Android threat rules. These interpret evidence only; they do
/// not collect platform signals, infer device trust, or make policy decisions.
final List<AssessmentRule> firstAndroidThreatRules = List.unmodifiable([
  AssessmentRule(
    id: 'android.root.su-binary-indicator.v1',
    threat: 'ANDROID_ROOT_EXECUTABLE_INDICATOR',
    severity: Severity.medium,
    reason: 'A known root-related executable path was observed.',
    requirements: [
      EvidenceRequirement(
        signalId: 'android.root.su_binary_present',
        expectedStatus: EvidenceStatus.detected,
        minimumConfidence: Confidence.medium,
      ),
    ],
  ),
  AssessmentRule(
    id: 'android.debugger-attached.v1',
    threat: 'ANDROID_DEBUGGER_ATTACHED',
    severity: Severity.medium,
    reason: 'The Android platform API reported a debugger attached at observation time.',
    requirements: [
      EvidenceRequirement(
        signalId: 'android.debugger.attached',
        expectedStatus: EvidenceStatus.detected,
        minimumConfidence: Confidence.high,
      ),
    ],
  ),
]);
