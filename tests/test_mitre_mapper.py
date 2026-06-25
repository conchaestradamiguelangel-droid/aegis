"""Tests for MITRE ATT&CK mapper (core/mitre_mapper.py)."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from core.mitre_mapper import map_incident


class TestMitreMapper:
    def test_mine_contact_gives_initial_access(self):
        r = map_incident("MINE_CONTACT", [], "UNKNOWN", "UNKNOWN")
        ids = [t["id"] for t in r["techniques"]]
        assert "T1190" in ids
        assert "initial-access" in r["tactics"]

    def test_recon_pattern_gives_reconnaissance(self):
        r = map_incident("RECON_PATTERN", [], "UNKNOWN", "UNKNOWN")
        ids = [t["id"] for t in r["techniques"]]
        assert "T1595" in ids
        assert "reconnaissance" in r["tactics"]

    def test_exploration_gives_discovery(self):
        r = map_incident("EXPLORATION", [], "UNKNOWN", "UNKNOWN")
        ids = [t["id"] for t in r["techniques"]]
        assert "T1046" in ids
        assert "discovery" in r["tactics"]

    def test_automated_gives_scanning(self):
        r = map_incident("AUTOMATED", [], "UNKNOWN", "UNKNOWN")
        ids = [t["id"] for t in r["techniques"]]
        assert "T1595.002" in ids

    def test_coordinated_gives_multiple_tactics(self):
        r = map_incident("COORDINATED", [], "UNKNOWN", "UNKNOWN")
        assert len(r["tactics"]) >= 2

    def test_forensic_credential_stuffing(self):
        r = map_incident("AUTOMATED", ["CREDENTIAL_STUFFING"], "UNKNOWN", "CREDENTIAL_THEFT")
        ids = [t["id"] for t in r["techniques"]]
        assert "T1110.004" in ids
        assert "credential-access" in r["tactics"]

    def test_bot_advanced_actor(self):
        r = map_incident("RECON_PATTERN", [], "BOT_ADVANCED", "UNKNOWN")
        ids = [t["id"] for t in r["techniques"]]
        assert "T1110" in ids

    def test_coverage_high_with_many_techniques(self):
        r = map_incident("COORDINATED", ["LATERAL_MOVEMENT"], "BOT_ADVANCED", "SYSTEM_ACCESS")
        assert r["coverage"] == "high"

    def test_unknown_inputs_return_empty_gracefully(self):
        r = map_incident("INVALID_TYPE", [], "INVALID_ACTOR", "INVALID_INTENT")
        assert r["techniques"] == []
        assert r["tactics"] == []
        assert r["coverage"] == "none"

    def test_each_technique_has_required_fields(self):
        r = map_incident("MINE_CONTACT", ["RECONNAISSANCE"], "BOT_SIMPLE", "RECONNAISSANCE")
        for tech in r["techniques"]:
            assert "id" in tech
            assert "name" in tech
            assert "tactic" in tech
            assert "url" in tech
            assert "attack.mitre.org" in tech["url"]
