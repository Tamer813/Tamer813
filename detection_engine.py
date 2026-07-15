"""Production-oriented detection engine for security event streams.

The module is intentionally dependency-light so it can run in constrained SOC
pipelines while still exposing extension points for REST and WebSocket adapters.
"""
from __future__ import annotations

import asyncio
import dataclasses
import fnmatch
import hashlib
import json
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yaml = None

Event = Dict[str, Any]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_WEIGHT = {
    Severity.INFO: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 95,
}


@dataclass(frozen=True)
class MitreAttackMapping:
    tactic: str
    technique: str
    technique_id: str
    subtechnique: Optional[str] = None


@dataclass(frozen=True)
class RuleVersion:
    version: str
    checksum: str
    created_at: str
    author: str = "system"
    notes: str = ""


@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    severity: Severity
    query: Mapping[str, Any]
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    mitre: List[MitreAttackMapping] = field(default_factory=list)
    risk: int = 50
    version: str = "1.0.0"
    schedule_interval_seconds: Optional[int] = None
    correlation: Optional[Mapping[str, Any]] = None
    custom_evaluator: Optional[Callable[[Event], bool]] = field(default=None, repr=False, compare=False)
    versions: List[RuleVersion] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity(str(self.severity).lower())
        self.risk = max(0, min(100, int(self.risk)))
        if not self.versions:
            self.versions.append(self.snapshot("initial"))

    def snapshot(self, notes: str = "") -> RuleVersion:
        payload = self.to_dict(include_versions=False)
        checksum = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return RuleVersion(self.version, checksum, utc_now(), notes=notes)

    def to_dict(self, include_versions: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "query": dict(self.query),
            "enabled": self.enabled,
            "tags": list(self.tags),
            "mitre": [dataclasses.asdict(item) for item in self.mitre],
            "risk": self.risk,
            "version": self.version,
            "schedule_interval_seconds": self.schedule_interval_seconds,
            "correlation": dict(self.correlation) if self.correlation else None,
        }
        if include_versions:
            data["versions"] = [dataclasses.asdict(v) for v in self.versions]
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], custom_evaluator: Optional[Callable[[Event], bool]] = None) -> "DetectionRule":
        mitre = [MitreAttackMapping(**m) for m in data.get("mitre", [])]
        rule = cls(
            id=str(data["id"]), name=str(data["name"]), description=str(data.get("description", "")),
            severity=Severity(str(data.get("severity", "medium")).lower()), query=dict(data.get("query", {})),
            enabled=bool(data.get("enabled", True)), tags=list(data.get("tags", [])), mitre=mitre,
            risk=int(data.get("risk", 50)), version=str(data.get("version", "1.0.0")),
            schedule_interval_seconds=data.get("schedule_interval_seconds"), correlation=data.get("correlation"),
            custom_evaluator=custom_evaluator,
        )
        if data.get("versions"):
            rule.versions = [RuleVersion(**v) for v in data["versions"]]
        return rule


@dataclass(frozen=True)
class Alert:
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    score: int
    risk_score: int
    event: Event
    mitre: List[MitreAttackMapping]
    created_at: str
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "rule_id": self.rule_id, "rule_name": self.rule_name,
            "severity": self.severity.value, "score": self.score, "risk_score": self.risk_score,
            "event": self.event, "mitre": [dataclasses.asdict(m) for m in self.mitre],
            "created_at": self.created_at, "correlation_id": self.correlation_id,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_path(event: Mapping[str, Any], path: str) -> Any:
    current: Any = event
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


class RuleEngine:
    """Evaluates DetectionRule query clauses against a single event."""
    def match(self, rule: DetectionRule, event: Event) -> bool:
        if not rule.enabled:
            return False
        if rule.custom_evaluator and not rule.custom_evaluator(event):
            return False
        return self._match_query(rule.query, event)

    def _match_query(self, query: Mapping[str, Any], event: Event) -> bool:
        if not query:
            return True
        if "all" in query:
            return all(self._match_query(q, event) for q in query["all"])
        if "any" in query:
            return any(self._match_query(q, event) for q in query["any"])
        if "not" in query:
            return not self._match_query(query["not"], event)
        field = str(query.get("field", ""))
        value = get_path(event, field)
        op = str(query.get("operator", "equals"))
        expected = query.get("value")
        return OPERATORS[op](value, expected)


OPERATORS: Dict[str, Callable[[Any, Any], bool]] = {
    "equals": lambda v, e: v == e,
    "not_equals": lambda v, e: v != e,
    "contains": lambda v, e: e in v if isinstance(v, (str, list, tuple, set, dict)) else False,
    "icontains": lambda v, e: str(e).lower() in str(v).lower(),
    "startswith": lambda v, e: str(v).startswith(str(e)),
    "endswith": lambda v, e: str(v).endswith(str(e)),
    "regex": lambda v, e: re.search(str(e), str(v or "")) is not None,
    "in": lambda v, e: v in e,
    "gt": lambda v, e: float(v) > float(e),
    "gte": lambda v, e: float(v) >= float(e),
    "lt": lambda v, e: float(v) < float(e),
    "lte": lambda v, e: float(v) <= float(e),
    "exists": lambda v, e: (v is not None) is bool(e),
    "wildcard": lambda v, e: fnmatch.fnmatch(str(v or ""), str(e)),
}


class SigmaRuleParser:
    """Converts a practical subset of Sigma YAML into DetectionRule objects."""
    LEVEL_MAP = {"informational": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}

    def loads(self, text: str) -> DetectionRule:
        if yaml:
            data = yaml.safe_load(text)
        else:
            data = self._minimal_yaml(text)
        detection = data.get("detection", {})
        selections = {k: v for k, v in detection.items() if k != "condition"}
        condition = detection.get("condition") or " and ".join(selections)
        query = self._condition_to_query(condition, selections)
        mitre = [MitreAttackMapping(tactic="unknown", technique=tag, technique_id=tag.split(".")[-1].upper()) for tag in data.get("tags", []) if str(tag).startswith("attack.")]
        return DetectionRule(
            id=str(data.get("id", uuid.uuid4())), name=str(data.get("title", "Sigma rule")),
            description=str(data.get("description", "")), severity=self.LEVEL_MAP.get(str(data.get("level", "medium")).lower(), Severity.MEDIUM),
            query=query, tags=list(data.get("tags", [])), mitre=mitre,
        )

    def _minimal_yaml(self, text: str) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        lines = [line.rstrip() for line in text.splitlines() if line.strip()]
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.startswith(" ") and ":" in line:
                key, value = line.split(":", 1)
                value = value.strip()
                if key == "detection":
                    detection: Dict[str, Any] = {}; i += 1
                    while i < len(lines) and lines[i].startswith(" "):
                        sub = lines[i].strip()
                        name, subval = sub.split(":", 1)
                        if subval.strip():
                            detection[name] = subval.strip(); i += 1; continue
                        i += 1; selection: Dict[str, Any] = {}
                        while i < len(lines) and lines[i].startswith("    "):
                            sk, sv = lines[i].strip().split(":", 1)
                            selection[sk] = sv.strip(); i += 1
                        detection[name] = selection
                    data[key] = detection; continue
                if value.startswith("[") and value.endswith("]"):
                    data[key] = [v.strip() for v in value[1:-1].split(",") if v.strip()]
                else:
                    data[key] = value
            i += 1
        return data

    def _selection_to_query(self, selection: Mapping[str, Any]) -> Mapping[str, Any]:
        clauses = []
        for key, value in selection.items():
            field, _, modifier = key.partition("|")
            op = {"contains": "icontains", "re": "regex", "startswith": "startswith", "endswith": "endswith"}.get(modifier, "equals")
            clauses.append({"field": field, "operator": op, "value": value})
        return {"all": clauses} if len(clauses) > 1 else clauses[0]

    def _condition_to_query(self, condition: str, selections: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
        tokens = condition.replace("(", " ").replace(")", " ").split()
        joiner = "any" if "or" in tokens else "all"
        names = [t for t in tokens if t not in {"and", "or", "not"} and t in selections]
        clauses = [self._selection_to_query(selections[name]) for name in names]
        return {joiner: clauses} if len(clauses) > 1 else (clauses[0] if clauses else {})


class EventCorrelator:
    def __init__(self, max_events: int = 10000):
        self.events: Deque[Tuple[float, Event]] = deque(maxlen=max_events)

    def add(self, event: Event) -> None:
        self.events.append((time.time(), event))

    def correlate(self, rule: DetectionRule, event: Event) -> Optional[str]:
        cfg = rule.correlation or {}
        if not cfg:
            return None
        field = cfg.get("field")
        threshold = int(cfg.get("threshold", 1))
        window = int(cfg.get("window_seconds", 300))
        value = get_path(event, str(field)) if field else None
        now = time.time()
        matches = [e for ts, e in self.events if now - ts <= window and (not field or get_path(e, str(field)) == value)]
        return str(uuid.uuid4()) if len(matches) >= threshold else None


class SeverityScorer:
    def score(self, rule: DetectionRule, event: Event) -> int:
        confidence = int(event.get("confidence", 75))
        return max(0, min(100, round((SEVERITY_WEIGHT[rule.severity] * 0.7) + (confidence * 0.3))))


class RiskScorer:
    def score(self, rule: DetectionRule, event: Event, severity_score: int) -> int:
        asset = int(event.get("asset_criticality", 50))
        return max(0, min(100, round(rule.risk * 0.4 + severity_score * 0.4 + asset * 0.2)))


class NotificationHub:
    """Async fan-out hub suitable for REST adapters and WebSocket bridges."""
    def __init__(self) -> None:
        self._subscribers: List[asyncio.Queue[Alert]] = []

    def subscribe(self) -> asyncio.Queue[Alert]:
        queue: asyncio.Queue[Alert] = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Alert]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    def publish(self, alert: Alert) -> None:
        for queue in list(self._subscribers):
            queue.put_nowait(alert)


class DetectionEngine:
    def __init__(self) -> None:
        self.rules: Dict[str, DetectionRule] = {}
        self.alerts: List[Alert] = []
        self.rule_engine = RuleEngine()
        self.correlator = EventCorrelator()
        self.severity_scorer = SeverityScorer()
        self.risk_scorer = RiskScorer()
        self.notifications = NotificationHub()

    def add_rule(self, rule: DetectionRule) -> None:
        self.rules[rule.id] = rule

    def update_rule(self, rule_id: str, **changes: Any) -> DetectionRule:
        rule = self.rules[rule_id]
        for key, value in changes.items():
            setattr(rule, key, value)
        rule.versions.append(rule.snapshot("update"))
        return rule

    def delete_rule(self, rule_id: str) -> None:
        del self.rules[rule_id]

    def process(self, event: Event) -> List[Alert]:
        self.correlator.add(event)
        generated: List[Alert] = []
        for rule in list(self.rules.values()):
            if self.rule_engine.match(rule, event):
                correlation_id = self.correlator.correlate(rule, event)
                sev_score = self.severity_scorer.score(rule, event)
                risk_score = self.risk_scorer.score(rule, event, sev_score)
                alert = Alert(str(uuid.uuid4()), rule.id, rule.name, rule.severity, sev_score, risk_score, dict(event), list(rule.mitre), utc_now(), correlation_id)
                self.alerts.append(alert)
                self.notifications.publish(alert)
                generated.append(alert)
        return generated

    def test_rule(self, rule: DetectionRule, events: Iterable[Event]) -> Dict[str, Any]:
        engine = DetectionEngine(); engine.add_rule(rule)
        alerts = [a for event in events for a in engine.process(event)]
        return {"rule_id": rule.id, "alerts": len(alerts), "matched_events": [a.event for a in alerts]}

    def export_rules(self) -> str:
        return json.dumps([r.to_dict() for r in self.rules.values()], indent=2, sort_keys=True)

    def import_rules(self, payload: str) -> None:
        for item in json.loads(payload):
            self.add_rule(DetectionRule.from_dict(item))


class RuleScheduler:
    def __init__(self, engine: DetectionEngine, event_provider: Callable[[], Iterable[Event]]) -> None:
        self.engine = engine; self.event_provider = event_provider; self._stop = threading.Event(); self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True); self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread: self._thread.join(timeout=5)

    def _run(self) -> None:
        last: Dict[str, float] = defaultdict(lambda: 0.0)
        while not self._stop.is_set():
            now = time.time()
            due = [r for r in self.engine.rules.values() if r.schedule_interval_seconds and now - last[r.id] >= r.schedule_interval_seconds]
            if due:
                for event in self.event_provider():
                    for rule in due:
                        if self.engine.rule_engine.match(rule, event): self.engine.process(event)
                for rule in due: last[rule.id] = now
            self._stop.wait(1)


class DetectionAPI:
    """Small stdlib REST API exposing rules, events, alerts, imports and tests."""
    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def handler(self):
        api = self
        class Handler(BaseHTTPRequestHandler):
            def _json(self, status: int, payload: Any) -> None:
                body = json.dumps(payload, default=str).encode(); self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            def _body(self) -> Any:
                return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            def do_GET(self):
                if self.path == "/rules": return self._json(200, [r.to_dict() for r in api.engine.rules.values()])
                if self.path == "/alerts": return self._json(200, [a.to_dict() for a in api.engine.alerts])
                return self._json(404, {"error": "not found"})
            def do_POST(self):
                body = self._body()
                if self.path == "/rules":
                    rule = DetectionRule.from_dict(body); api.engine.add_rule(rule); return self._json(201, rule.to_dict())
                if self.path == "/events": return self._json(200, [a.to_dict() for a in api.engine.process(body)])
                if self.path == "/rules/import": api.engine.import_rules(json.dumps(body)); return self._json(204, {})
                if self.path == "/rules/test": return self._json(200, api.engine.test_rule(DetectionRule.from_dict(body["rule"]), body.get("events", [])))
                return self._json(404, {"error": "not found"})
        return Handler

    def serve(self, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
        server = ThreadingHTTPServer((host, port), self.handler())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server
