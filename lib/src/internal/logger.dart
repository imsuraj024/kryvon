import 'dart:developer' as developer;

import '../core/threat_event.dart';
import 'log_level.dart';

class KryvonLogger {
  static LogLevel _level = LogLevel.info;

  static void configure({
    LogLevel level = LogLevel.info,
  }) {
    _level = level;
  }

  static void debug(String message, {Map<String, dynamic>? metadata}) {
    _log(LogLevel.debug, message, metadata);
  }

  static void info(String message, {Map<String, dynamic>? metadata}) {
    _log(LogLevel.info, message, metadata);
  }

  static void warning(String message, {Map<String, dynamic>? metadata}) {
    _log(LogLevel.warning, message, metadata);
  }

  static void error(String message, {Map<String, dynamic>? metadata}) {
    _log(LogLevel.error, message, metadata);
  }

  static void threat(ThreatEvent event) {
    _log(
      LogLevel.warning,
      "Security threat detected: ${event.type.name}",
      {
        "severity": event.severity.name,
        ...?event.metadata,
      },
    );
  }

  static void _log(
    LogLevel level,
    String message,
    Map<String, dynamic>? metadata,
  ) {
    if (_level == LogLevel.silent) return;
    if (level.index < _level.index) return;

    final formatted = "[Kryvon][${level.name.toUpperCase()}] $message ${metadata ?? ''}";
    print(formatted);

    developer.log(
      message,
      name: "Kryvon",
      error: level == LogLevel.error ? metadata : null,
    );
  }
}