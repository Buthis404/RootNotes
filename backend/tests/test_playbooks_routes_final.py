import pytest
from unittest.mock import MagicMock, patch

from app.routers.playbooks.routes import router
from app.routers.playbooks._models import PlaybookBody, PlaybookRunBody, BatchRunBody, OperationPackCreate
from app.routers.playbooks._validation import _validate_playbook_payload
from app.routers.playbooks._data import BUILTIN_PLAYBOOKS, STEP_TEMPLATES


class TestPlaybookModels:
    def test_playbook_body_defaults(self):
        body = PlaybookBody(title="Test", description="", steps=[])
        assert body.title == "Test"

    def test_run_body_defaults(self):
        body = PlaybookRunBody()
        assert body.target == ""
        assert body.target_url == ""

    def test_batch_run_body(self):
        body = BatchRunBody(host_ids=[], parallelism=5)
        assert body.parallelism == 5

    def test_operation_pack_create(self):
        body = OperationPackCreate(name="pack1", steps=[], tags=[])
        assert body.name == "pack1"


class TestValidatePlaybook:
    def test_valid(self):
        result = _validate_playbook_payload(PlaybookBody(title="Test", description="", steps=[]), [])
        assert "ok" in result

    def test_with_steps(self):
        steps = [{"title": "Step 1", "connector_key": "ssh", "operation": "exec", "params": {}}]
        result = _validate_playbook_payload(PlaybookBody(title="Test", description="", steps=steps), [{"key": "ssh"}])
        assert "ok" in result


class TestBuiltinPlaybooks:
    def test_exists(self):
        assert isinstance(BUILTIN_PLAYBOOKS, dict)

    def test_step_templates(self):
        assert isinstance(STEP_TEMPLATES, dict)
