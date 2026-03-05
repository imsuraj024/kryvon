import 'threat_event.dart';

/// Contract that every Kryvon security guard must implement.
///
/// Guards are registered via [Kryvon.registerGuard] and executed in parallel
/// by [Kryvon.runChecks]. A guard should be stateless and idempotent.
abstract class Guard {
  /// Runs this guard's security checks and returns any detected threats.
  ///
  /// Returns an empty list when no threats are found. Must not throw;
  /// unhandled exceptions are caught by the runtime and treated as an empty
  /// result so that sibling guards are not blocked.
  Future<List<ThreatEvent>> check();
}