# Milestone 5: Detection Engine

The detection engine provides a production-oriented, dependency-light SOC rule pipeline:

- **Detection Engine Core**: `DetectionEngine` stores rules, processes events, emits alerts, and exports/imports rule packs.
- **Rule Engine**: `RuleEngine` supports boolean clauses plus equality, string, regex, numeric, existence, membership, and wildcard operators.
- **Sigma Rule Support**: `SigmaRuleParser` imports common Sigma YAML selections, conditions, levels, and ATT&CK tags.
- **Custom Detection Rules**: `DetectionRule.custom_evaluator` enables Python callbacks alongside declarative queries.
- **Event Correlation**: `EventCorrelator` correlates by field, threshold, and time window.
- **MITRE ATT&CK Mapping**: `MitreAttackMapping` attaches tactics and techniques to rules and alerts.
- **Rule Scheduler**: `RuleScheduler` periodically evaluates scheduled rules against an event provider.
- **Severity and Risk Scoring**: `SeverityScorer` and `RiskScorer` combine rule severity, confidence, asset criticality, and rule risk.
- **Alert Generation**: `Alert` records rule, event, scoring, ATT&CK, correlation, and timestamps.
- **Rule Versioning**: every rule carries checksum-based `RuleVersion` snapshots and records updates.
- **Rule Testing**: `DetectionEngine.test_rule` validates a rule against sample events.
- **Rule Import/Export**: JSON import/export preserves version history and rule metadata.
- **REST APIs**: `DetectionAPI` exposes `/rules`, `/events`, `/alerts`, `/rules/import`, and `/rules/test`.
- **WebSocket Notifications**: `NotificationHub` provides async fan-out queues that WebSocket adapters can bridge to connected clients.

## Example

```python
from detection_engine import DetectionEngine, DetectionRule, Severity

engine = DetectionEngine()
engine.add_rule(DetectionRule(
    id="auth-admin-login",
    name="Admin Login",
    description="Detect admin logins",
    severity=Severity.HIGH,
    query={"field": "user", "operator": "equals", "value": "admin"},
    risk=80,
))
alerts = engine.process({"user": "admin", "confidence": 90, "asset_criticality": 100})
```

## Testing

Run the unit and integration suite with:

```bash
python -m unittest discover -s tests
```
