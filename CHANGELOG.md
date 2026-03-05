## 0.1.0

* Guards run in parallel via `Future.wait`
* `RuntimeRiskAggregator` computes a weighted risk score across all guard results
* Enforcement now acts on the aggregated `deviceCompromised` event
* Refined root severity mapping (`writableSystem` → high, `knownRootApp`/`testKeys` → medium, fallback → low)
* Guard failures are isolated — errors are logged and do not abort the run

## 0.0.1

* Initial release — Android only
* Policy-based threat detection framework (`Kryvon.initialize` + `Kryvon.runChecks`)
* Root detection with 6 native indicators: `suBinary`, `suExecution`, `dangerousProps`, `writableSystem`, `knownRootApp`, `testKeys`
* Severity levels: `low` → `medium` → `high` → `critical`
* Enforcement strategies: `emitOnly`, `terminateApp`
* Built-in `KryvonPolicy.fintech()` preset
* Structured logger with configurable log level
