/// Runtime security assessment and policy engine for Flutter applications.
///
/// Kryvon separates platform observations from threat interpretation, risk
/// evaluation, and host-owned enforcement decisions. Platform checks are
/// local indicators, not remote attestation; sensitive operations must still
/// be authorized by a trusted backend.
library kryvon;

export 'src/domain/assessment.dart';
export 'src/domain/decision.dart';
export 'src/domain/evidence.dart';
export 'src/domain/kryvon_enums.dart';
export 'src/domain/policy.dart';
export 'src/domain/risk.dart';
export 'src/domain/signal_run.dart';
export 'src/engine/kryvon_engine.dart';

export 'src/engine/detector.dart';
export 'src/engine/detector_orchestrator.dart';
export 'src/engine/assessment_generator.dart';
export 'src/engine/first_android_threat_rules.dart';
export 'src/engine/android_platform_detector.dart';
