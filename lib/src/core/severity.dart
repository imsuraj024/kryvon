/// Indicates how serious a detected threat is.
///
/// Values are ordered from least to most severe so that ordinal comparisons
/// (e.g. `severity.index >= threshold.index`) work as expected.
enum ThreatSeverity {
  /// Informational — unlikely to pose an immediate risk.
  low,

  /// Moderate risk; worth monitoring but not immediately blocking.
  medium,

  /// Significant risk; consider blocking sensitive operations.
  high,

  /// Severe risk; immediate enforcement action is recommended.
  critical,
}