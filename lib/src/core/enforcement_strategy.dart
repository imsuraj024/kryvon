/// Defines what action Kryvon takes when a threat exceeds the block threshold.
enum EnforcementStrategy {
  /// Log the threat and fire [KryvonPolicy.onThreat], but take no further action.
  emitOnly,

  /// Terminate the application process immediately via [exit(1)].
  terminateApp,

  /// Terminate the application process immediately. Used for critical threats
  /// such as hook or integrity failures where any leniency is unacceptable.
  blockApp,

  /// Restrict sensitive application features without terminating the process.
  /// The host app is expected to check [KryvonPolicy.onThreat] and gate
  /// premium or sensitive flows accordingly.
  restrictFeatures,
}