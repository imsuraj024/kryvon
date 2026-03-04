import 'package:kryvon/src/core/enforcement_executor.dart';
import 'package:kryvon/src/internal/log_level.dart';
import 'package:kryvon/src/internal/logger.dart';
import 'package:kryvon/src/runtime/root/root_guard.dart';

import 'guard.dart';
import 'kryvon_policy.dart';

class Kryvon {
  static late KryvonPolicy _policy;
  static final List<Guard> _guards = [];

  static void initialize({
    required KryvonPolicy policy,
    LogLevel logLevel = LogLevel.info,
  }) {
    _policy = policy;
    KryvonLogger.configure(level: logLevel);
    
    // Auto-register root guard
    if (!_guards.any((g) => g is RootGuard)) {
      registerGuard(RootGuard());
    }

    KryvonLogger.info("Kryvon initialized");
  }

  static void registerGuard(Guard guard) {
    _guards.add(guard);
    KryvonLogger.debug("Registered guards count: ${_guards.length}");
  }

  static Future<void> runChecks() async {
    KryvonLogger.debug("Running security guards");
    for (final guard in _guards) {
      try {
      final events = await guard.check();

      for (final event in events) {
        KryvonLogger.threat(event);

        _policy.onThreat?.call(event);

        if (_policy.shouldBlock(event)) {
          EnforcementExecutor.execute(
            strategy: _policy.enforcementStrategy,
            event: event,
          );
        }
      }
    } catch (e) {
      KryvonLogger.error(
        "Guard execution failed",
        metadata: {"error": e.toString()},
      );
    }
    }
  }
}