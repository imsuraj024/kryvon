## 0.0.1

* Initial release — Android only
* Policy-based threat detection framework (`Kryvon.initialize` + `Kryvon.runChecks`)
* Root detection with 6 native indicators: `suBinary`, `suExecution`, `dangerousProps`, `writableSystem`, `knownRootApp`, `testKeys`
* Severity levels: `low` → `medium` → `high` → `critical`
* Enforcement strategies: `emitOnly`, `terminateApp`
* Built-in `KryvonPolicy.fintech()` preset
* Structured logger with configurable log level
