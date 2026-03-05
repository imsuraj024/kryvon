/// Defines what action Kryvon takes when a threat exceeds the block threshold.
enum EnforcementStrategy {
  /// Log the threat and fire [KryvonPolicy.onThreat], but take no further action.
  emitOnly,

  /// Terminate the application process immediately via [exit(1)].
  terminateApp,
}