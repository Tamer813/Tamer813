import json
import unittest
from urllib import request

from detection_engine import DetectionAPI, DetectionEngine, DetectionRule, Severity, SigmaRuleParser


class DetectionEngineTests(unittest.TestCase):
    def rule(self):
        return DetectionRule(
            id="r1", name="Admin login", description="admin login detected", severity=Severity.HIGH,
            query={"all": [{"field": "user", "operator": "equals", "value": "admin"}, {"field": "action", "operator": "equals", "value": "login"}]},
            risk=80, mitre=[], correlation={"field": "source.ip", "threshold": 1, "window_seconds": 60},
        )

    def test_alert_generation_scoring_and_export(self):
        engine = DetectionEngine(); engine.add_rule(self.rule())
        alerts = engine.process({"user": "admin", "action": "login", "source": {"ip": "1.2.3.4"}, "confidence": 90, "asset_criticality": 100})
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.HIGH)
        self.assertGreaterEqual(alerts[0].risk_score, 80)
        clone = DetectionEngine(); clone.import_rules(engine.export_rules())
        self.assertIn("r1", clone.rules)

    def test_sigma_parser_and_rule_testing(self):
        sigma = '''
title: Suspicious PowerShell
id: sigma-1
level: high
tags: [attack.t1059]
detection:
  selection:
    process.name: powershell.exe
    command|contains: encodedcommand
  condition: selection
'''
        rule = SigmaRuleParser().loads(sigma)
        result = DetectionEngine().test_rule(rule, [{"process": {"name": "powershell.exe"}, "command": "-EncodedCommand abc"}])
        self.assertEqual(result["alerts"], 1)
        self.assertEqual(rule.mitre[0].technique_id, "T1059")

    def test_rest_api(self):
        engine = DetectionEngine(); server = DetectionAPI(engine).serve(port=0)
        base = f"http://127.0.0.1:{server.server_port}"
        data = json.dumps(self.rule().to_dict()).encode()
        req = request.Request(base + "/rules", data=data, headers={"Content-Type": "application/json"}, method="POST")
        self.assertEqual(request.urlopen(req, timeout=5).status, 201)
        event = json.dumps({"user": "admin", "action": "login"}).encode()
        req = request.Request(base + "/events", data=event, headers={"Content-Type": "application/json"}, method="POST")
        self.assertEqual(len(json.loads(request.urlopen(req, timeout=5).read())), 1)
        server.shutdown(); server.server_close()


if __name__ == "__main__":
    unittest.main()
