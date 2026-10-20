import 'dart:async';

import 'package:flutter/services.dart';

import '../domain/evidence.dart';
import '../domain/kryvon_enums.dart';
import 'detector.dart';

/// Android-only detector for the first explicitly documented Kryvon signals.
///
/// Native results are untrusted input. Every response is correlated with the
/// request and validated before it becomes Evidence. Channel errors and
/// timeouts become FAILED evidence with stable diagnostic codes.
class AndroidPlatformDetector implements SignalDetector {
  AndroidPlatformDetector({
    MethodChannel? channel,
    this.timeout = const Duration(seconds: 2),
  }) : _channel = channel ?? const MethodChannel('dev.kryvon/security.v1') {
    if (timeout <= Duration.zero) {
      throw ArgumentError.value(
        timeout,
        'timeout',
        'Timeout must be positive.',
      );
    }
  }

  final MethodChannel _channel;
  final Duration timeout;

  static const rootSuBinarySignal = 'android.root.su_binary_present';
  static const debuggerAttachedSignal = 'android.debugger.attached';

  static const List<String> _signals = <String>[
    rootSuBinarySignal,
    debuggerAttachedSignal,
  ];

  @override
  String get id => 'android.platform.security.v1';

  @override
  List<String> get signalIds => List<String>.unmodifiable(_signals);

  @override
  Future<Evidence> evaluate(DetectorRequest request) async {
    if (!_signals.contains(request.signalId)) {
      return _evidence(
        request,
        status: EvidenceStatus.unsupported,
        confidence: null,
        source: 'kryvon.android.channel',
        metadata: const <String, Object?>{
          'diagnosticCode': 'unsupported_signal',
        },
      );
    }
    if (request.platform.trim().toLowerCase() != 'android') {
      return _evidence(
        request,
        status: EvidenceStatus.unsupported,
        confidence: null,
        source: 'kryvon.android.channel',
        metadata: const <String, Object?>{
          'diagnosticCode': 'platform_unsupported',
        },
      );
    }

    try {
      final response = await _channel
          .invokeMapMethod<String, Object?>('evaluateSignal', <String, Object?>{
            'protocolVersion': 1,
            'requestId': request.requestId,
            'signalId': request.signalId,
            'context': request.context.name,
            'configuration': request.configuration,
          })
          .timeout(timeout);
      return _parseResponse(request, response);
    } on TimeoutException {
      return _failed(request, 'channel_timeout');
    } on MissingPluginException {
      return _failed(request, 'channel_unavailable');
    } on PlatformException {
      return _failed(request, 'native_platform_error');
    } on FormatException {
      return _failed(request, 'malformed_native_response');
    } on Object {
      return _failed(request, 'native_adapter_error');
    }
  }

  Evidence _parseResponse(
    DetectorRequest request,
    Map<String, Object?>? response,
  ) {
    if (response == null ||
        response['protocolVersion'] != 1 ||
        response['requestId'] != request.requestId ||
        response['signalId'] != request.signalId) {
      return _failed(request, 'invalid_response_correlation');
    }

    final status = _parseStatus(response['status']);
    final confidence = _parseConfidence(response['confidence']);
    final source = response['source'];
    final platform = response['platform'];
    final observedAtValue = response['observedAt'];
    final metadataValue = response['metadata'];

    if (status == null ||
        source is! String ||
        source.trim().isEmpty ||
        platform != 'android' ||
        observedAtValue is! String ||
        !observedAtValue.endsWith('Z') ||
        metadataValue is! Map ||
        metadataValue.keys.any((key) => key is! String) ||
        !_isJsonValue(metadataValue, 0) ||
        (response['confidence'] != null && confidence == null) ||
        (status == EvidenceStatus.detected && confidence == null)) {
      return _failed(request, 'malformed_native_response');
    }

    final observedAt = DateTime.tryParse(observedAtValue);
    if (observedAt == null || !observedAt.isUtc) {
      return _failed(request, 'malformed_native_timestamp');
    }

    return Evidence(
      signal: request.signalId,
      status: status,
      confidence: confidence,
      source: source,
      platform: 'android',
      observedAt: observedAt,
      metadata: Map<String, Object?>.from(metadataValue),
    );
  }

  Evidence _failed(DetectorRequest request, String code) => _evidence(
    request,
    status: EvidenceStatus.failed,
    confidence: null,
    source: 'kryvon.android.channel',
    metadata: <String, Object?>{'diagnosticCode': code},
  );

  Evidence _evidence(
    DetectorRequest request, {
    required EvidenceStatus status,
    required Confidence? confidence,
    required String source,
    required Map<String, Object?> metadata,
  }) => Evidence(
    signal: request.signalId,
    status: status,
    confidence: confidence,
    source: source,
    platform: request.platform.trim().isEmpty
        ? 'unknown'
        : request.platform.trim().toLowerCase(),
    observedAt: DateTime.now().toUtc(),
    metadata: metadata,
  );

  static EvidenceStatus? _parseStatus(Object? value) {
    switch (value) {
      case 'detected':
        return EvidenceStatus.detected;
      case 'not_detected':
        return EvidenceStatus.notDetected;
      case 'unknown':
        return EvidenceStatus.unknown;
      case 'failed':
        return EvidenceStatus.failed;
      case 'unsupported':
        return EvidenceStatus.unsupported;
      default:
        return null;
    }
  }

  static Confidence? _parseConfidence(Object? value) {
    switch (value) {
      case null:
        return null;
      case 'low':
        return Confidence.low;
      case 'medium':
        return Confidence.medium;
      case 'high':
        return Confidence.high;
      default:
        return null;
    }
  }

  static bool _isJsonValue(Object? value, int depth) {
    if (depth > 8) return false;
    if (value == null || value is String || value is bool || value is num) {
      return true;
    }
    if (value is List) {
      return value.every((item) => _isJsonValue(item, depth + 1));
    }
    if (value is Map) {
      return value.entries.every(
        (entry) => entry.key is String && _isJsonValue(entry.value, depth + 1),
      );
    }
    return false;
  }
}
