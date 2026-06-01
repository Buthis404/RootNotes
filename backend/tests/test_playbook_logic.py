"""Unit tests for playbook branching and validation logic."""
from app.routers.playbooks import (
    _condition_matches,
    _extract_result_value,
    _normalize_branch_action,
    _resolve_next_step_index,
    _resolve_result_condition_target,
    _validate_playbook_payload,
    PlaybookBody,
    PlaybookStepBody,
)


# ---------------------------------------------------------------------------
# _condition_matches
# ---------------------------------------------------------------------------

class TestConditionMatches:
    def test_eq_match(self):
        assert _condition_matches(5, "eq", 5)

    def test_eq_no_match(self):
        assert not _condition_matches(5, "eq", 6)

    def test_ne_match(self):
        assert _condition_matches(5, "ne", 6)

    def test_ne_no_match(self):
        assert not _condition_matches(5, "ne", 5)

    def test_gt_match(self):
        assert _condition_matches(10, "gt", 5)

    def test_gt_no_match_equal(self):
        assert not _condition_matches(5, "gt", 5)

    def test_gte_match_equal(self):
        assert _condition_matches(5, "gte", 5)

    def test_gte_match_greater(self):
        assert _condition_matches(6, "gte", 5)

    def test_gte_no_match(self):
        assert not _condition_matches(4, "gte", 5)

    def test_lt_match(self):
        assert _condition_matches(3, "lt", 5)

    def test_lte_match_equal(self):
        assert _condition_matches(5, "lte", 5)

    def test_contains_string(self):
        assert _condition_matches("hello world", "contains", "hello")

    def test_contains_string_no_match(self):
        assert not _condition_matches("hello world", "contains", "xyz")

    def test_contains_list(self):
        assert _condition_matches([1, 2, 3], "contains", 2)

    def test_contains_non_container(self):
        assert not _condition_matches(42, "contains", 4)

    def test_numeric_string_coercion(self):
        # "5" and 5 should be treated as equal for gt/lt
        assert _condition_matches("10", "gt", "5")

    def test_non_numeric_comparison_returns_false(self):
        assert not _condition_matches("abc", "gt", "def")

    def test_eq_zero(self):
        assert _condition_matches(0, "eq", 0)

    def test_gt_zero(self):
        assert _condition_matches(1, "gt", 0)


# ---------------------------------------------------------------------------
# _extract_result_value
# ---------------------------------------------------------------------------

class TestExtractResultValue:
    def test_simple_key(self):
        assert _extract_result_value({"hosts_found": 3}, "hosts_found") == 3

    def test_nested_key(self):
        assert _extract_result_value({"a": {"b": {"c": 42}}}, "a.b.c") == 42

    def test_missing_top_key(self):
        assert _extract_result_value({}, "missing") is None

    def test_missing_nested_key(self):
        assert _extract_result_value({"a": {"b": 1}}, "a.c") is None

    def test_non_dict_intermediate(self):
        assert _extract_result_value({"a": 5}, "a.b") is None

    def test_zero_value_returned(self):
        assert _extract_result_value({"count": 0}, "count") == 0

    def test_empty_result(self):
        assert _extract_result_value({}, "anything") is None


# ---------------------------------------------------------------------------
# _normalize_branch_action
# ---------------------------------------------------------------------------

class TestNormalizeBranchAction:
    def test_none_success_returns_next(self):
        assert _normalize_branch_action(None, success=True) == "next"

    def test_none_failure_returns_stop(self):
        assert _normalize_branch_action(None, success=False) == "stop"

    def test_continue_normalizes_to_next(self):
        assert _normalize_branch_action("continue", success=True) == "next"

    def test_stop_passthrough(self):
        assert _normalize_branch_action("stop", success=True) == "stop"

    def test_jump_passthrough(self):
        assert _normalize_branch_action("jump", success=True) == "jump"

    def test_uppercase_normalized(self):
        assert _normalize_branch_action("NEXT", success=True) == "next"

    def test_whitespace_stripped(self):
        assert _normalize_branch_action("  next  ", success=True) == "next"


# ---------------------------------------------------------------------------
# _resolve_next_step_index
# ---------------------------------------------------------------------------

class TestResolveNextStepIndex:
    def test_next_advances(self):
        step = {"on_success": "next"}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) == 1

    def test_next_at_last_step_returns_none(self):
        step = {"on_success": "next"}
        assert _resolve_next_step_index(step, success=True, current_idx=2, total_steps=3) is None

    def test_stop_returns_none(self):
        step = {"on_success": "stop"}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) is None

    def test_jump_to_valid_step(self):
        step = {"on_success": "jump", "on_success_step": 3}
        # step 3 = index 2
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) == 2

    def test_jump_to_out_of_range_returns_none(self):
        step = {"on_success": "jump", "on_success_step": 99}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) is None

    def test_jump_to_step_zero_invalid(self):
        step = {"on_success": "jump", "on_success_step": 0}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) is None

    def test_failure_stop_by_default(self):
        step = {}
        assert _resolve_next_step_index(step, success=False, current_idx=0, total_steps=3) is None

    def test_failure_continue(self):
        step = {"on_failure": "continue"}
        assert _resolve_next_step_index(step, success=False, current_idx=1, total_steps=3) == 2

    def test_failure_jump(self):
        step = {"on_failure": "jump", "on_failure_step": 2}
        assert _resolve_next_step_index(step, success=False, current_idx=0, total_steps=3) == 1

    def test_jump_missing_step_target(self):
        step = {"on_success": "jump", "on_success_step": None}
        assert _resolve_next_step_index(step, success=True, current_idx=0, total_steps=3) is None


# ---------------------------------------------------------------------------
# _resolve_result_condition_target
# ---------------------------------------------------------------------------

class TestResolveResultConditionTarget:
    def _step(self, rules):
        return {"result_conditions": rules}

    def test_no_conditions_returns_no_override(self):
        idx, stop = _resolve_result_condition_target({}, {}, status="done", total_steps=3)
        assert idx is None and not stop

    def test_condition_match_action_stop(self):
        step = self._step([{
            "when": "success", "result_key": "hosts_found",
            "operator": "eq", "value": 0, "action": "stop"
        }])
        idx, stop = _resolve_result_condition_target(step, {"hosts_found": 0}, status="done", total_steps=3)
        assert idx is None and stop

    def test_condition_match_action_next(self):
        step = self._step([{
            "when": "success", "result_key": "hosts_found",
            "operator": "gt", "value": 0, "action": "next"
        }])
        idx, stop = _resolve_result_condition_target(step, {"hosts_found": 5}, status="done", total_steps=3)
        assert idx is None and not stop

    def test_condition_match_action_jump(self):
        step = self._step([{
            "when": "success", "result_key": "findings_created",
            "operator": "gt", "value": 0, "action": "jump", "target_step": 3
        }])
        idx, stop = _resolve_result_condition_target(step, {"findings_created": 2}, status="done", total_steps=3)
        assert idx == 2 and not stop

    def test_condition_when_success_skipped_on_failure(self):
        step = self._step([{
            "when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "stop"
        }])
        idx, stop = _resolve_result_condition_target(step, {"x": 1}, status="failed", total_steps=3)
        assert idx is None and not stop

    def test_condition_when_failure_applied_on_failure(self):
        step = self._step([{
            "when": "failure", "result_key": "x", "operator": "eq", "value": 1, "action": "stop"
        }])
        idx, stop = _resolve_result_condition_target(step, {"x": 1}, status="failed", total_steps=3)
        assert stop

    def test_condition_when_always_applies_on_success(self):
        step = self._step([{
            "when": "always", "result_key": "x", "operator": "eq", "value": 0, "action": "stop"
        }])
        idx, stop = _resolve_result_condition_target(step, {"x": 0}, status="done", total_steps=3)
        assert stop

    def test_condition_when_always_applies_on_failure(self):
        step = self._step([{
            "when": "always", "result_key": "x", "operator": "eq", "value": 0, "action": "stop"
        }])
        idx, stop = _resolve_result_condition_target(step, {"x": 0}, status="failed", total_steps=3)
        assert stop

    def test_condition_no_match_returns_no_override(self):
        step = self._step([{
            "when": "success", "result_key": "hosts_found",
            "operator": "gt", "value": 100, "action": "stop"
        }])
        idx, stop = _resolve_result_condition_target(step, {"hosts_found": 3}, status="done", total_steps=3)
        assert idx is None and not stop

    def test_invalid_jump_target_returns_stop(self):
        step = self._step([{
            "when": "success", "result_key": "x", "operator": "eq", "value": 1,
            "action": "jump", "target_step": 99
        }])
        idx, stop = _resolve_result_condition_target(step, {"x": 1}, status="done", total_steps=3)
        assert idx is None and stop

    def test_first_matching_rule_wins(self):
        step = self._step([
            {"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "stop"},
            {"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "jump", "target_step": 2},
        ])
        idx, stop = _resolve_result_condition_target(step, {"x": 1}, status="done", total_steps=3)
        assert stop  # first rule won


# ---------------------------------------------------------------------------
# _validate_playbook_payload
# ---------------------------------------------------------------------------

MOCK_CONNECTORS = [
    {"key": "nmap", "supported_operations": ["scan"]},
    {"key": "topology", "supported_operations": ["auto_build", "rebuild_layout"]},
    {"key": "nuclei", "supported_operations": ["scan"]},
]


def _make_step(**kwargs) -> PlaybookStepBody:
    defaults = {
        "title": "Test Step",
        "connector_key": "nmap",
        "operation": "scan",
        "params": {},
        "on_success": "next",
        "on_failure": "stop",
        "result_conditions": [],
    }
    defaults.update(kwargs)
    return PlaybookStepBody(**defaults)


class TestValidatePlaybookPayload:
    def test_empty_title_error(self):
        body = PlaybookBody(title="   ", steps=[_make_step()])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("Title" in e for e in result["errors"])

    def test_no_steps_error(self):
        body = PlaybookBody(title="My Playbook", steps=[])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("step" in e.lower() for e in result["errors"])

    def test_unknown_connector_error(self):
        body = PlaybookBody(title="Test", steps=[_make_step(connector_key="unknown_tool")])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("unknown_tool" in e for e in result["errors"])

    def test_unsupported_operation_error(self):
        body = PlaybookBody(title="Test", steps=[_make_step(connector_key="nmap", operation="exec")])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("exec" in e for e in result["errors"])

    def test_jump_without_target_step_error(self):
        body = PlaybookBody(title="Test", steps=[
            _make_step(on_success="jump", on_success_step=None)
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("on_success_step" in e for e in result["errors"])

    def test_jump_out_of_range_error(self):
        body = PlaybookBody(title="Test", steps=[
            _make_step(on_success="jump", on_success_step=99)
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("on_success_step" in e for e in result["errors"])

    def test_valid_single_step(self):
        body = PlaybookBody(title="Valid", steps=[_make_step()])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert result["ok"]
        assert result["errors"] == []

    def test_valid_jump_within_range(self):
        body = PlaybookBody(title="Valid", steps=[
            _make_step(on_success="jump", on_success_step=2),
            _make_step(connector_key="topology", operation="auto_build"),
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert result["ok"]

    def test_normalized_output_contains_steps(self):
        body = PlaybookBody(title="  My Plan  ", steps=[_make_step()])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert result["ok"]
        assert result["normalized"]["title"] == "My Plan"
        assert len(result["normalized"]["steps"]) == 1

    def test_condition_invalid_operator_error(self):
        body = PlaybookBody(title="Test", steps=[
            _make_step(result_conditions=[{
                "when": "success", "result_key": "x", "operator": "invalid_op", "value": 1, "action": "stop"
            }])
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("operator" in e for e in result["errors"])

    def test_condition_missing_result_key_error(self):
        body = PlaybookBody(title="Test", steps=[
            _make_step(result_conditions=[{
                "when": "success", "result_key": "", "operator": "eq", "value": 1, "action": "stop"
            }])
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("result_key" in e for e in result["errors"])

    def test_condition_jump_without_target_step_error(self):
        body = PlaybookBody(title="Test", steps=[
            _make_step(result_conditions=[{
                "when": "success", "result_key": "x", "operator": "eq",
                "value": 1, "action": "jump"
            }])
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("target_step" in e for e in result["errors"])

    def test_unknown_param_generates_warning(self):
        body = PlaybookBody(title="Test", steps=[
            _make_step(params={"target": "10.0.0.1", "unknown_param": "value"})
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert result["ok"]
        assert any("unknown_param" in w for w in result["warnings"])

    def test_failure_jump_missing_target(self):
        body = PlaybookBody(title="Test", steps=[
            _make_step(on_failure="jump", on_failure_step=None)
        ])
        result = _validate_playbook_payload(body, MOCK_CONNECTORS)
        assert not result["ok"]
        assert any("on_failure_step" in e for e in result["errors"])

    def test_empty_connector_list_rejects_all_steps(self):
        body = PlaybookBody(title="Test", steps=[_make_step()])
        result = _validate_playbook_payload(body, [])
        assert not result["ok"]
