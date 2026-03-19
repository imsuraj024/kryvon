/// Result produced by [IntegrityDetector] after querying the native runtime.
class IntegrityDetectionResult {
  /// `true` when the app's integrity checks passed (no tampering detected).
  final bool integrityOk;

  /// Names of the individual integrity checks that failed.
  ///
  /// Possible values: `signatureMismatch`, `signatureUnavailable`,
  /// `unknownInstaller`.
  final List<String> indicators;

  /// The SHA-256 hex digest of the live signing certificate.
  ///
  /// `null` when the certificate could not be read.
  final String? liveSha256;

  const IntegrityDetectionResult({
    required this.integrityOk,
    required this.indicators,
    this.liveSha256,
  });
}
