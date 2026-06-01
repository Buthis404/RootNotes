"""Extended MITRE tests — helper functions."""
from unittest.mock import MagicMock

from app.routers.mitre import (
    TACTIC_ORDER,
    _kb_to_technique,
    _index_attack_steps,
)


class TestKbToTechnique:
    def test_with_mitre_id_and_tactic(self):
        article = MagicMock()
        article.tags = ["T1059", "lateral_movement"]
        article.title = "T1059 — Command and Scripting Interpreter"
        article.id = "kb1"
        result = _kb_to_technique(article)
        assert result["id"] == "T1059"
        assert result["tactic"] == "Lateral Movement"
        assert result["name"] == "Command and Scripting Interpreter"
        assert result["kb_id"] == "kb1"

    def test_title_without_em_dash(self):
        article = MagicMock()
        article.tags = ["T1234"]
        article.title = "Simple Title"
        article.id = "kb2"
        result = _kb_to_technique(article)
        assert result["name"] == "Simple Title"

    def test_empty_tags(self):
        article = MagicMock()
        article.tags = []
        article.title = "No Tags"
        article.id = "kb3"
        result = _kb_to_technique(article)
        assert result["id"] == ""

    def test_unknown_tactic(self):
        article = MagicMock()
        article.tags = ["T1111", "unknown_phase"]
        article.title = "Test"
        article.id = "kb4"
        result = _kb_to_technique(article)
        assert result["tactic"] == ""


class TestIndexAttackSteps:
    def test_indexes_steps(self):
        s1 = MagicMock()
        s1.mitre_id = "T1059"
        s1.technique = "PowerShell"
        s1.id = "s1"
        s1.label = "PS Exec"
        s2 = MagicMock()
        s2.mitre_id = ""
        s2.technique = ""
        s2.id = "s2"
        s2.label = ""
        used_ids, used_names = _index_attack_steps([s1, s2])
        assert "T1059" in used_ids
        assert "powershell" in used_names
        assert len(used_names["powershell"]) == 1

    def test_empty_steps(self):
        used_ids, used_names = _index_attack_steps([])
        assert used_ids == set()
        assert used_names == {}


class TestTacticOrder:
    def test_tactics_present(self):
        assert "Initial Access" in TACTIC_ORDER
        assert "Lateral Movement" in TACTIC_ORDER
        assert len(TACTIC_ORDER) == 13
