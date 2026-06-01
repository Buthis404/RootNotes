"""
Extended tests for playbook validation functions.
"""

import pytest
from unittest.mock import MagicMock

from app.routers.playbooks._validation import (
    _step_deps_zero_idx,
    _reconstruct_cycle_path,
    _detect_cycle,
    _is_dag_mode,
    _normalize_precondition,
    _evaluate_precondition,
    _normalize_field_value,
    _normalize_branch_action,
    _normalize_condition,
    _condition_matches,
    _extract_result_value,
    _condition_rule_applies,
    _resolve_matched_action,
    _resolve_result_condition_target,
    _validate_dep_values,
    _validate_retry_config,
    _validate_precondition_fields,
    _validate_dag_constraints,
    _validate_one_condition,
    CONDITION_OPERATORS,
    RETRY_STATUSES,
)


class TestStepDepsZeroIdx:
    def test_empty_deps_no_default(self):
        assert _step_deps_zero_idx({}) == []

    def test_empty_deps_with_default(self):
        assert _step_deps_zero_idx({}, default_prev=2) == [2]

    def test_single_dep(self):
        assert _step_deps_zero_idx({"depends_on": [3]}) == [2]

    def test_multiple_deps(self):
        assert _step_deps_zero_idx({"depends_on": [1, 3, 5]}) == [0, 2, 4]

    def test_invalid_dep_ignored(self):
        assert _step_deps_zero_idx({"depends_on": ["abc"]}) == []

    def test_mixed_valid_invalid(self):
        result = _step_deps_zero_idx({"depends_on": [2, "bad", 4]})
        assert result == [1, 3]

    def test_empty_deps_with_default_prev(self):
        result = _step_deps_zero_idx({}, default_prev=0)
        assert result == [0]

    def test_deps_override_default(self):
        result = _step_deps_zero_idx({"depends_on": [1]}, default_prev=3)
        assert result == [0]


class TestReconstructCyclePath:
    def test_direct_cycle(self):
        parent = {0: 1, 1: 0}
        path = _reconstruct_cycle_path(1, 0, parent)
        assert path == [0, 1, 0]

    def test_longer_cycle(self):
        parent = {2: 1, 1: 0}
        path = _reconstruct_cycle_path(2, 0, parent)
        assert path == [0, 1, 2, 0]

    def test_no_parent_path(self):
        parent = {}
        path = _reconstruct_cycle_path(0, 1, parent)
        assert 0 in path


class TestDetectCycle:
    def test_no_cycle(self):
        adj = {0: [1], 1: [2], 2: []}
        assert _detect_cycle(adj, 3) is None

    def test_simple_cycle(self):
        adj = {0: [1], 1: [0]}
        result = _detect_cycle(adj, 2)
        assert result is not None
        assert len(result) > 0

    def test_self_loop(self):
        adj = {0: [0]}
        result = _detect_cycle(adj, 1)
        assert result is not None

    def test_three_node_cycle(self):
        adj = {0: [1], 1: [2], 2: [0]}
        result = _detect_cycle(adj, 3)
        assert result is not None

    def test_disconnected_no_cycle(self):
        adj = {0: [], 1: [], 2: []}
        assert _detect_cycle(adj, 3) is None

    def test_out_of_range_neighbors_ignored(self):
        adj = {0: [5], 1: []}
        assert _detect_cycle(adj, 2) is None

    def test_negative_neighbors_ignored(self):
        adj = {0: [-1], 1: []}
        assert _detect_cycle(adj, 2) is None

    def test_empty_graph(self):
        assert _detect_cycle({}, 0) is None


class TestIsDagMode:
    def test_no_special_fields(self):
        steps = [{"connector_key": "nmap"}, {"connector_key": "nuclei"}]
        assert _is_dag_mode(steps) is False

    def test_depends_on(self):
        steps = [{"connector_key": "nmap", "depends_on": [1]}]
        assert _is_dag_mode(steps) is True

    def test_retry_count(self):
        steps = [{"connector_key": "nmap", "retry_count": 2}]
        assert _is_dag_mode(steps) is True

    def test_precondition(self):
        steps = [{"connector_key": "nmap", "precondition": {"step": 1}}]
        assert _is_dag_mode(steps) is True

    def test_zero_retry_count_not_dag(self):
        steps = [{"connector_key": "nmap", "retry_count": 0}]
        assert _is_dag_mode(steps) is False

    def test_empty_steps(self):
        assert _is_dag_mode([]) is False


class TestNormalizePrecondition:
    def test_none(self):
        assert _normalize_precondition(None) is None

    def test_empty_dict(self):
        assert _normalize_precondition({}) is None

    def test_full_rule(self):
        rule = {"step": 2, "result_key": "hosts_found", "operator": "gt", "value": 0, "negate": True}
        result = _normalize_precondition(rule)
        assert result["step"] == 2
        assert result["result_key"] == "hosts_found"
        assert result["operator"] == "gt"
        assert result["value"] == 0
        assert result["negate"] is True

    def test_step_string_converted(self):
        result = _normalize_precondition({"step": "3"})
        assert result["step"] == 3

    def test_step_invalid_string(self):
        result = _normalize_precondition({"step": "abc"})
        assert result["step"] is None

    def test_default_operator(self):
        result = _normalize_precondition({"result_key": "x"})
        assert result["operator"] == "eq"

    def test_default_negate(self):
        result = _normalize_precondition({"result_key": "x"})
        assert result["negate"] is False

    def test_non_dict(self):
        assert _normalize_precondition("not a dict") is None


class TestEvaluatePrecondition:
    def test_empty_pre(self):
        assert _evaluate_precondition({}, {}, []) is True

    def test_none_pre(self):
        assert _evaluate_precondition(None, {}, []) is True

    def test_ref_step_done_match(self):
        pre = {"step": 1, "result_key": "hosts_found", "operator": "eq", "value": 5, "negate": False}
        state = {0: {"status": "done", "result_json": {"hosts_found": 5}}}
        assert _evaluate_precondition(pre, state, []) is True

    def test_ref_step_done_no_match(self):
        pre = {"step": 1, "result_key": "hosts_found", "operator": "eq", "value": 10, "negate": False}
        state = {0: {"status": "done", "result_json": {"hosts_found": 5}}}
        assert _evaluate_precondition(pre, state, []) is False

    def test_negate(self):
        pre = {"step": 1, "result_key": "hosts_found", "operator": "eq", "value": 10, "negate": True}
        state = {0: {"status": "done", "result_json": {"hosts_found": 5}}}
        assert _evaluate_precondition(pre, state, []) is True

    def test_ref_step_not_done(self):
        pre = {"step": 1, "result_key": "hosts_found", "operator": "eq", "value": 5, "negate": False}
        state = {0: {"status": "failed", "result_json": {}}}
        assert _evaluate_precondition(pre, state, []) is False

    def test_ref_step_not_done_negate(self):
        pre = {"step": 1, "result_key": "hosts_found", "operator": "eq", "value": 5, "negate": True}
        state = {0: {"status": "failed", "result_json": {}}}
        assert _evaluate_precondition(pre, state, []) is True

    def test_no_step_ref_uses_last_dep(self):
        pre = {"step": None, "result_key": "hosts_found", "operator": "gt", "value": 0, "negate": False}
        state = {1: {"status": "done", "result_json": {"hosts_found": 3}}}
        assert _evaluate_precondition(pre, state, [1]) is True

    def test_no_step_no_deps(self):
        pre = {"step": None, "result_key": "hosts_found", "operator": "gt", "value": 0, "negate": False}
        assert _evaluate_precondition(pre, {}, []) is True

    def test_state_missing_target(self):
        pre = {"step": 3, "result_key": "x", "operator": "eq", "value": 1, "negate": False}
        state = {}
        assert _evaluate_precondition(pre, state, []) is False


class TestNormalizeFieldValue:
    def test_number_type(self):
        field = {"type": "number"}
        assert _normalize_field_value(field, "42") == 42

    def test_number_type_invalid(self):
        field = {"type": "number", "default": 10}
        assert _normalize_field_value(field, "abc") == 10

    def test_boolean_type_true(self):
        field = {"type": "boolean"}
        assert _normalize_field_value(field, True) is True

    def test_boolean_type_false(self):
        field = {"type": "boolean"}
        assert _normalize_field_value(field, False) is False

    def test_text_type(self):
        field = {"type": "text"}
        assert _normalize_field_value(field, "hello") == "hello"

    def test_text_type_none(self):
        field = {"type": "text"}
        assert _normalize_field_value(field, None) == ""

    def test_default_type(self):
        field = {}
        assert _normalize_field_value(field, "val") == "val"

    def test_no_type_none_value(self):
        field = {}
        assert _normalize_field_value(field, None) == ""


class TestNormalizeCondition:
    def test_full_rule(self):
        rule = {"when": "success", "result_key": "x", "operator": "gt", "value": 0, "action": "stop", "target_step": None}
        result = _normalize_condition(rule)
        assert result["when"] == "success"
        assert result["operator"] == "gt"
        assert result["action"] == "stop"

    def test_defaults(self):
        rule = {}
        result = _normalize_condition(rule)
        assert result["when"] == "success"
        assert result["operator"] == "eq"
        assert result["result_key"] == ""

    def test_continue_normalized(self):
        rule = {"action": "continue"}
        result = _normalize_condition(rule)
        assert result["action"] == "next"

    def test_whitespace_stripped(self):
        rule = {"when": "  success  ", "result_key": "  x  ", "operator": "  eq  "}
        result = _normalize_condition(rule)
        assert result["when"] == "success"
        assert result["result_key"] == "x"
        assert result["operator"] == "eq"


class TestConditionRuleApplies:
    def test_success_on_done(self):
        rule = {"when": "success"}
        assert _condition_rule_applies(rule, "done") is True

    def test_success_on_failed(self):
        rule = {"when": "success"}
        assert _condition_rule_applies(rule, "failed") is False

    def test_failure_on_failed(self):
        rule = {"when": "failure"}
        assert _condition_rule_applies(rule, "failed") is True

    def test_failure_on_done(self):
        rule = {"when": "failure"}
        assert _condition_rule_applies(rule, "done") is False

    def test_always_on_done(self):
        rule = {"when": "always"}
        assert _condition_rule_applies(rule, "done") is True

    def test_always_on_failed(self):
        rule = {"when": "always"}
        assert _condition_rule_applies(rule, "failed") is True

    def test_invalid_when(self):
        rule = {"when": "invalid"}
        assert _condition_rule_applies(rule, "done") is False


class TestResolveMatchedAction:
    def test_stop(self):
        idx, stop = _resolve_matched_action({"action": "stop"}, total_steps=3)
        assert idx is None
        assert stop is True

    def test_jump_valid(self):
        idx, stop = _resolve_matched_action({"action": "jump", "target_step": 2}, total_steps=3)
        assert idx == 1
        assert stop is False

    def test_jump_invalid(self):
        idx, stop = _resolve_matched_action({"action": "jump", "target_step": 99}, total_steps=3)
        assert idx is None
        assert stop is True

    def test_jump_none_target(self):
        idx, stop = _resolve_matched_action({"action": "jump", "target_step": None}, total_steps=3)
        assert idx is None
        assert stop is True

    def test_next(self):
        idx, stop = _resolve_matched_action({"action": "next"}, total_steps=3)
        assert idx is None
        assert stop is False

    def test_jump_boundary(self):
        idx, stop = _resolve_matched_action({"action": "jump", "target_step": 1}, total_steps=3)
        assert idx == 0
        assert stop is False


class TestResolveResultConditionTarget:
    def _step(self, rules):
        return {"result_conditions": rules}

    def test_no_conditions(self):
        step = self._step([])
        idx, stop = _resolve_result_condition_target(step, {}, status="done", total_steps=3)
        assert idx is None and not stop

    def test_condition_match_stop(self):
        step = self._step([{"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "stop"}])
        idx, stop = _resolve_result_condition_target(step, {"x": 1}, status="done", total_steps=3)
        assert stop

    def test_condition_no_match(self):
        step = self._step([{"when": "success", "result_key": "x", "operator": "eq", "value": 99, "action": "stop"}])
        idx, stop = _resolve_result_condition_target(step, {"x": 1}, status="done", total_steps=3)
        assert not stop

    def test_condition_failure_on_done_skipped(self):
        step = self._step([{"when": "failure", "result_key": "x", "operator": "eq", "value": 1, "action": "stop"}])
        idx, stop = _resolve_result_condition_target(step, {"x": 1}, status="done", total_steps=3)
        assert not stop

    def test_nested_key(self):
        step = self._step([{"when": "success", "result_key": "a.b", "operator": "eq", "value": 1, "action": "stop"}])
        idx, stop = _resolve_result_condition_target(step, {"a": {"b": 1}}, status="done", total_steps=3)
        assert stop


class TestValidateDepValues:
    def test_valid_deps(self):
        errors = []
        result = _validate_dep_values("Step 1", [2, 3], 0, 5, errors)
        assert result == [2, 3]
        assert errors == []

    def test_self_dep(self):
        errors = []
        result = _validate_dep_values("Step 2", [2], 1, 5, errors)
        assert result == []
        assert any("itself" in e for e in errors)

    def test_out_of_range(self):
        errors = []
        result = _validate_dep_values("Step 1", [10], 0, 3, errors)
        assert result == []
        assert any("out of range" in e for e in errors)

    def test_non_int(self):
        errors = []
        result = _validate_dep_values("Step 1", ["abc"], 0, 3, errors)
        assert result == []
        assert any("integers" in e for e in errors)

    def test_dedup(self):
        errors = []
        result = _validate_dep_values("Step 1", [2, 2], 0, 5, errors)
        assert result == [2]

    def test_none_deps(self):
        errors = []
        result = _validate_dep_values("Step 1", None, 0, 3, errors)
        assert result == []


class TestValidateRetryConfig:
    def test_defaults(self):
        step = MagicMock()
        step.retry_count = 0
        step.retry_delay_seconds = 0
        step.retry_on = ["failed"]
        count, delay, on = _validate_retry_config("S1", step, [])
        assert count == 0
        assert delay == 0
        assert on == ["failed"]

    def test_negative_count(self):
        step = MagicMock()
        step.retry_count = -1
        step.retry_delay_seconds = 0
        step.retry_on = ["failed"]
        errors = []
        count, delay, on = _validate_retry_config("S1", step, errors)
        assert count == 0
        assert any("retry_count" in e for e in errors)

    def test_too_high_count(self):
        step = MagicMock()
        step.retry_count = 20
        step.retry_delay_seconds = 0
        step.retry_on = ["failed"]
        errors = []
        count, delay, on = _validate_retry_config("S1", step, errors)
        assert count == 10

    def test_negative_delay(self):
        step = MagicMock()
        step.retry_count = 0
        step.retry_delay_seconds = -5
        step.retry_on = ["failed"]
        errors = []
        count, delay, on = _validate_retry_config("S1", step, errors)
        assert delay == 0
        assert any("retry_delay" in e for e in errors)

    def test_too_high_delay(self):
        step = MagicMock()
        step.retry_count = 0
        step.retry_delay_seconds = 5000
        step.retry_on = ["failed"]
        errors = []
        count, delay, on = _validate_retry_config("S1", step, errors)
        assert delay == 3600

    def test_invalid_retry_on(self):
        step = MagicMock()
        step.retry_count = 1
        step.retry_delay_seconds = 5
        step.retry_on = ["invalid"]
        errors = []
        count, delay, on = _validate_retry_config("S1", step, errors)
        assert on == ["failed"]

    def test_empty_retry_on(self):
        step = MagicMock()
        step.retry_count = 1
        step.retry_delay_seconds = 5
        step.retry_on = []
        errors = []
        count, delay, on = _validate_retry_config("S1", step, errors)
        assert on == ["failed"]


class TestValidatePreconditionFields:
    def test_missing_result_key(self):
        errors = []
        pre = {"result_key": "", "operator": "eq", "step": None}
        _validate_precondition_fields("S1", pre, 0, 3, errors)
        assert any("result_key" in e for e in errors)

    def test_invalid_operator(self):
        errors = []
        pre = {"result_key": "x", "operator": "bad_op", "step": None}
        _validate_precondition_fields("S1", pre, 0, 3, errors)
        assert any("operator" in e for e in errors)

    def test_step_out_of_range(self):
        errors = []
        pre = {"result_key": "x", "operator": "eq", "step": 10}
        _validate_precondition_fields("S1", pre, 0, 3, errors)
        assert any("out of range" in e for e in errors)

    def test_step_self_reference(self):
        errors = []
        pre = {"result_key": "x", "operator": "eq", "step": 1}
        _validate_precondition_fields("Step 1", pre, 0, 3, errors)
        assert any("own step" in e for e in errors)

    def test_valid_precondition(self):
        errors = []
        pre = {"result_key": "x", "operator": "eq", "step": 2}
        _validate_precondition_fields("S1", pre, 0, 3, errors)
        assert errors == []


class TestValidateDagConstraints:
    def test_cycle_detected(self):
        steps = [
            {"depends_on": [2]},
            {"depends_on": [1]},
        ]
        errors = []
        warnings = []
        _validate_dag_constraints(steps, 2, errors, warnings)
        assert any("cycle" in e.lower() for e in errors)

    def test_jump_in_dag(self):
        steps = [
            {"depends_on": [], "on_success": "jump"},
        ]
        errors = []
        warnings = []
        _validate_dag_constraints(steps, 1, errors, warnings)
        assert any("jump" in e for e in errors)

    def test_precondition_not_in_deps(self):
        steps = [
            {"depends_on": [], "precondition": {"step": 2}},
        ]
        errors = []
        warnings = []
        _validate_dag_constraints(steps, 1, errors, warnings)
        assert any("precondition" in w for w in warnings)

    def test_no_issues(self):
        steps = [
            {"depends_on": []},
            {"depends_on": [1]},
        ]
        errors = []
        warnings = []
        _validate_dag_constraints(steps, 2, errors, warnings)
        assert errors == []
        assert warnings == []


class TestValidateOneCondition:
    def test_valid_condition(self):
        errors = []
        rule = {"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "stop"}
        result = _validate_one_condition("S1", 0, rule, 3, errors)
        assert result["when"] == "success"
        assert errors == []

    def test_invalid_when(self):
        errors = []
        rule = {"when": "bad", "result_key": "x", "operator": "eq", "value": 1, "action": "stop"}
        _validate_one_condition("S1", 0, rule, 3, errors)
        assert any("when" in e for e in errors)

    def test_missing_result_key(self):
        errors = []
        rule = {"when": "success", "result_key": "", "operator": "eq", "value": 1, "action": "stop"}
        _validate_one_condition("S1", 0, rule, 3, errors)
        assert any("result_key" in e for e in errors)

    def test_invalid_operator(self):
        errors = []
        rule = {"when": "success", "result_key": "x", "operator": "bad", "value": 1, "action": "stop"}
        _validate_one_condition("S1", 0, rule, 3, errors)
        assert any("operator" in e for e in errors)

    def test_invalid_action(self):
        errors = []
        rule = {"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "bad"}
        _validate_one_condition("S1", 0, rule, 3, errors)
        assert any("action" in e for e in errors)

    def test_jump_without_target(self):
        errors = []
        rule = {"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "jump"}
        _validate_one_condition("S1", 0, rule, 3, errors)
        assert any("target_step" in e for e in errors)

    def test_jump_out_of_range(self):
        errors = []
        rule = {"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "jump", "target_step": 99}
        _validate_one_condition("S1", 0, rule, 3, errors)
        assert any("target_step" in e for e in errors)

    def test_jump_valid_target(self):
        errors = []
        rule = {"when": "success", "result_key": "x", "operator": "eq", "value": 1, "action": "jump", "target_step": 2}
        result = _validate_one_condition("S1", 0, rule, 3, errors)
        assert errors == []
        assert result["action"] == "jump"


class TestConditionConstants:
    def test_operators_set(self):
        expected = {"eq", "ne", "gt", "gte", "lt", "lte", "contains"}
        assert CONDITION_OPERATORS == expected

    def test_retry_statuses(self):
        expected = {"failed", "cancelled", "timeout"}
        assert RETRY_STATUSES == expected


class TestConditionMatchesExtended:
    def test_lt_no_match(self):
        assert not _condition_matches(10, "lt", 5)

    def test_lte_no_match(self):
        assert not _condition_matches(6, "lte", 5)

    def test_unknown_operator(self):
        assert not _condition_matches(5, "unknown", 5)

    def test_contains_set(self):
        assert _condition_matches({1, 2, 3}, "contains", 2)

    def test_contains_tuple(self):
        assert _condition_matches((1, 2, 3), "contains", 2)


class TestExtractResultValueExtended:
    def test_deeply_nested(self):
        data = {"a": {"b": {"c": {"d": 99}}}}
        assert _extract_result_value(data, "a.b.c.d") == 99

    def test_empty_key(self):
        assert _extract_result_value({"": "val"}, "") == "val"

    def test_list_intermediate(self):
        assert _extract_result_value({"a": [1, 2, 3]}, "a.b") is None
