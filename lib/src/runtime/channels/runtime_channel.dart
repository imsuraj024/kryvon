import 'dart:math';

import 'package:flutter/services.dart';

/// Contract for the native security bridge.
///
/// Every call must carry a nonce; the implementation validates that the
/// response echoes the same nonce before trusting any payload.
abstract class SecureRuntimeBridge {
  Future<Map<dynamic, dynamic>> invoke(
    String method, {
    Map<String, dynamic>? arguments,
  });
}

/// [SecureRuntimeBridge] backed by a Flutter [MethodChannel].
///
/// Security guarantees:
/// - A cryptographically random nonce is attached to every outgoing request.
/// - The response must echo the same nonce under the `__nonce` key.
/// - Any failure (null result, nonce mismatch, exception) returns
///   `{'__compromised': true}` — never a soft error.
class MethodChannelBridge implements SecureRuntimeBridge {
  MethodChannelBridge(this._channel);

  final MethodChannel _channel;
  final Random _rng = Random.secure();

  String _nonce() {
    return List.generate(16, (_) => _rng.nextInt(256))
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  @override
  Future<Map<dynamic, dynamic>> invoke(
    String method, {
    Map<String, dynamic>? arguments,
  }) async {
    final nonce = _nonce();
    final args = <String, dynamic>{
      ...?arguments,
      '__nonce': nonce,
    };

    try {
      final result = await _channel.invokeMethod<Map>(method, args);

      if (result == null) {
        return const {'__compromised': true, '__reason': 'null_response'};
      }

      // Validate nonce echo — reject if missing or mismatched.
      if (result['__nonce'] != nonce) {
        return const {'__compromised': true, '__reason': 'nonce_mismatch'};
      }

      return result;
    } on PlatformException catch (e) {
      return {'__compromised': true, '__reason': e.code};
    } on MissingPluginException {
      return const {'__compromised': true, '__reason': 'plugin_missing'};
    } catch (_) {
      return const {'__compromised': true, '__reason': 'unknown'};
    }
  }
}

/// Low-level bridge to the native security runtime.
///
/// The channel name is XOR-obfuscated to impede static analysis.
/// All calls are routed through an injected [SecureRuntimeBridge] so the
/// transport layer is swappable and nonce-validated without touching guard logic.
///
/// Call [RuntimeChannel.initialize] once, before [Kryvon.initialize].
/// If not called explicitly, the default [MethodChannelBridge] is used.
class RuntimeChannel {
  // "com.kryvon.runtime" XOR 0x5A — decoded lazily at runtime.
  static final MethodChannel _defaultChannel = MethodChannel(_decodeName());

  static late SecureRuntimeBridge _bridge;
  static bool _initialized = false;

  static String _decodeName() {
    const encoded = [
      0x39, 0x35, 0x37, 0x74, 0x31, 0x28, 0x23, 0x2C,
      0x35, 0x34, 0x74, 0x28, 0x2F, 0x34, 0x2E, 0x33,
      0x37, 0x3F,
    ];
    return String.fromCharCodes(encoded.map((b) => b ^ 0x5A));
  }

  /// Inject a [SecureRuntimeBridge] implementation.
  ///
  /// Falls back to [MethodChannelBridge] with the obfuscated channel if not
  /// called explicitly.  Call this before [Kryvon.initialize] if you need
  /// a custom bridge (e.g. in tests).
  static void initialize([SecureRuntimeBridge? bridge]) {
    _bridge = bridge ?? MethodChannelBridge(_defaultChannel);
    _initialized = true;
  }

  static Future<Map<dynamic, dynamic>> _invoke(
    String method, {
    Map<String, dynamic>? arguments,
  }) {
    if (!_initialized) initialize();
    return _bridge.invoke(method, arguments: arguments);
  }

  static Future<Map<dynamic, dynamic>> checkRoot() => _invoke('checkRoot');

  static Future<Map<dynamic, dynamic>> checkDebugger() =>
      _invoke('checkDebugger');

  static Future<Map<dynamic, dynamic>> checkHook() => _invoke('checkHook');

  static Future<Map<dynamic, dynamic>> checkEmulator() =>
      _invoke('checkEmulator');

  static Future<Map<dynamic, dynamic>> checkIntegrity({
    String? expectedSignatureSha256,
  }) =>
      _invoke(
        'checkIntegrity',
        arguments: expectedSignatureSha256 != null
            ? {'expectedSha256': expectedSignatureSha256}
            : null,
      );
}
