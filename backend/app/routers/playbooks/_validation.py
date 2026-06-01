from ._data import STEP_TEMPLATES
from ._models import PlaybookBody

CONDITION_OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "contains"}

RETRY_STATUSES = {"failed", "cancelled", "timeout"}


def _step_deps_zero_idx(step: dict, default_prev: int | None = None) -> list[int]:
    """Return 0-based dep indices for a normalized step.

    If `depends_on` is empty we fall back to the implicit "previous step" model
    (default_prev), so existing linear playbooks still execute correctly under
    the DAG runner.
    """
    deps = step.get("depends_on") or []
    out = []
    for d in deps:
        try:
            out.append(int(d) - 1)
        except Exception:
            continue
    if not out and default_prev is not None:
        out.append(default_prev)
    return out


def _reconstruct_cycle_path(u: int, v: int, parent: dict[int, int]) -> list[int]:
    path = [u]
    cur = u
    while cur != v and cur in parent:
        cur = parent[cur]
        path.append(cur)
    path.reverse()
    path.append(v)
    return path



def _detect_cycle_dfs(u: int, adj: dict, n: int, color: dict, parent: dict, cycle_path: list) -> bool:
    _, GRAY, _ = 0, 1, 2
    color[u] = GRAY
    for v in adj.get(u, []):
        if v < 0 or v >= n:
            continue
        if color[v] == 1:
            cycle_path.extend(_reconstruct_cycle_path(u, v, parent))
            return True
        if color[v] == 0:
            parent[v] = u
            if _detect_cycle_dfs(v, adj, n, color, parent, cycle_path):
                return True
    color[u] = 2
    return False

def _detect_cycle(adj: dict[int, list[int]], n: int) -> list[int] | None:
    """Return a cycle as a list of 0-based step indices, or None if acyclic."""
    color = dict.fromkeys(range(n), 0)
    parent: dict[int, int] = {}
    cycle_path: list[int] = []

    for i in range(n):
        if color[i] == 0 and _detect_cycle_dfs(i, adj, n, color, parent, cycle_path):
            return cycle_path
    return None


def _is_dag_mode(steps: list[dict]) -> bool:
    """A playbook switches to DAG runner if any step opts into the new fields."""
    for s in steps:
        if s.get("depends_on"):
            return True
        if int(s.get("retry_count") or 0) > 0:
            return True
        if s.get("precondition"):
            return True
    return False


def _normalize_precondition(rule: dict | None) -> dict | None:
    if not rule or not isinstance(rule, dict):
        return None
    step_ref = rule.get("step")
    try:
        step_ref = int(step_ref) if step_ref is not None else None
    except Exception:
        step_ref = None
    return {
        "step": step_ref,  # 1-based; None → most recent dep
        "result_key": str(rule.get("result_key") or "").strip(),
        "operator": str(rule.get("operator") or "eq").strip().lower(),
        "value": rule.get("value"),
        "negate": bool(rule.get("negate", False)),
    }


def _evaluate_precondition(pre: dict, state: dict[int, dict], deps: list[int]) -> bool:
    """Return True if the step is eligible to run. False ⇒ skip."""
    if not pre:
        return True
    target_idx = pre.get("step")
    if target_idx is not None:
        target_idx = int(target_idx) - 1
    elif deps:
        target_idx = deps[-1]
    else:
        return True  # no reference, nothing to evaluate
    target_state = state.get(target_idx)
    if not target_state or target_state.get("status") != "done":
        # Referenced step did not complete successfully → precondition can't be true
        return bool(pre.get("negate", False))
    result_payload = target_state.get("result_json") or {}
    actual = _extract_result_value(result_payload, pre.get("result_key") or "")
    matched = _condition_matches(actual, pre.get("operator") or "eq", pre.get("value"))
    return (not matched) if pre.get("negate") else matched


def _template_for(connector_key: str, operation: str) -> dict | None:
    return STEP_TEMPLATES.get(f"{connector_key}:{operation}")


def _normalize_field_value(field: dict, value):
    if field.get("type") == "number":
        try:
            return int(value)
        except Exception:
            return field.get("default", 0)
    if field.get("type") == "boolean":
        return bool(value)
    return "" if value is None else value


def _normalize_branch_action(value: str | None, *, success: bool) -> str:
    if not value:
        return "next" if success else "stop"
    value = value.strip().lower()
    if value == "continue":
        return "next"
    return value


def _normalize_condition(rule: dict) -> dict:
    return {
        "when": (rule.get("when") or "success").strip().lower(),
        "result_key": str(rule.get("result_key") or "").strip(),
        "operator": str(rule.get("operator") or "eq").strip().lower(),
        "value": rule.get("value"),
        "action": _normalize_branch_action(rule.get("action"), success=True),
        "target_step": rule.get("target_step"),
    }


def _extract_result_value(result: dict, result_key: str):
    current = result
    for part in result_key.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _condition_matches(actual, operator: str, expected) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "ne":
        return actual != expected
    if operator == "contains":
        return expected in actual if isinstance(actual, (str, list, tuple, set)) else False
    try:
        a = float(actual)
        b = float(expected)
    except Exception:
        return False
    if operator == "gt":
        return a > b
    if operator == "gte":
        return a >= b
    if operator == "lt":
        return a < b
    if operator == "lte":
        return a <= b
    return False


def _validate_step_branching(prefix: str, step, total_steps: int, errors: list) -> tuple[str, str]:
    on_success = _normalize_branch_action(step.on_success, success=True)
    on_failure = _normalize_branch_action(step.on_failure, success=False)
    if on_success not in {"next", "stop", "jump"}:
        errors.append(f"{prefix}: on_success must be 'next', 'stop', or 'jump'")
    if on_failure not in {"next", "stop", "jump"}:
        errors.append(f"{prefix}: on_failure must be 'stop', 'next', or 'jump'")
    if on_success == "jump":
        if step.on_success_step is None:
            errors.append(f"{prefix}: on_success_step is required when on_success='jump'")
        elif step.on_success_step < 1 or step.on_success_step > total_steps:
            errors.append(f"{prefix}: on_success_step must be between 1 and {total_steps}")
    if on_failure == "jump":
        if step.on_failure_step is None:
            errors.append(f"{prefix}: on_failure_step is required when on_failure='jump'")
        elif step.on_failure_step < 1 or step.on_failure_step > total_steps:
            errors.append(f"{prefix}: on_failure_step must be between 1 and {total_steps}")
    return on_success, on_failure


def _validate_one_condition(prefix: str, ridx: int, raw_rule: dict, total_steps: int, errors: list) -> dict:
    cond = _normalize_condition(raw_rule)
    if cond["when"] not in {"success", "failure", "always"}:
        errors.append(f"{prefix}: condition {ridx + 1} has invalid when value")
    if not cond["result_key"]:
        errors.append(f"{prefix}: condition {ridx + 1} requires result_key")
    if cond["operator"] not in CONDITION_OPERATORS:
        errors.append(f"{prefix}: condition {ridx + 1} has invalid operator")
    if cond["action"] not in {"next", "stop", "jump"}:
        errors.append(f"{prefix}: condition {ridx + 1} has invalid action")
    if cond["action"] == "jump":
        if cond["target_step"] is None:
            errors.append(
                f"{prefix}: condition {ridx + 1} requires target_step when action='jump'"
            )
        elif cond["target_step"] < 1 or cond["target_step"] > total_steps:
            errors.append(
                f"{prefix}: condition {ridx + 1} target_step must be between 1 and {total_steps}"
            )
    return cond


def _validate_step_conditions(prefix: str, step, total_steps: int, errors: list) -> list[dict]:
    normalized_conditions = []
    for ridx, raw_rule in enumerate(step.result_conditions or []):
        cond = _validate_one_condition(prefix, ridx, raw_rule, total_steps, errors)
        normalized_conditions.append(cond)
    return normalized_conditions


def _validate_step_params(prefix: str, step, params: dict, errors: list, warnings: list) -> dict:
    template = _template_for(step.connector_key, step.operation)
    if not template:
        return params
    allowed = {field["key"]: field for field in template.get("fields", [])}
    unknown = [key for key in params.keys() if key not in allowed]
    if unknown:
        warnings.append(
            f"{prefix}: unknown params will be ignored: {', '.join(sorted(unknown))}"
        )
    normalized_params = {}
    for key, field in allowed.items():
        value = params.get(key, field.get("default"))
        if field.get("required") and str(value).strip() == "":
            errors.append(f"{prefix}: field {key!r} is required")
        normalized_params[key] = _normalize_field_value(field, value)
    return normalized_params


def _validate_dep_values(prefix: str, raw_deps, idx: int, total_steps: int, errors: list) -> list[int]:
    norm: list[int] = []
    for raw_dep in raw_deps or []:
        try:
            d = int(raw_dep)
        except Exception:
            errors.append(f"{prefix}: depends_on values must be integers")
            continue
        if d < 1 or d > total_steps:
            errors.append(f"{prefix}: depends_on={d} is out of range 1..{total_steps}")
            continue
        if d == idx + 1:
            errors.append(f"{prefix}: a step cannot depend on itself")
            continue
        if d not in norm:
            norm.append(d)
    return norm


def _validate_retry_config(prefix: str, step, errors: list) -> tuple[int, int, list[str]]:
    retry_count = int(step.retry_count or 0)
    if retry_count < 0 or retry_count > 10:
        errors.append(f"{prefix}: retry_count must be 0..10")
        retry_count = max(0, min(10, retry_count))
    retry_delay = int(step.retry_delay_seconds or 0)
    if retry_delay < 0 or retry_delay > 3600:
        errors.append(f"{prefix}: retry_delay_seconds must be 0..3600")
        retry_delay = max(0, min(3600, retry_delay))
    retry_on = [s for s in (step.retry_on or ["failed"]) if s in RETRY_STATUSES]
    if not retry_on:
        retry_on = ["failed"]
    return retry_count, retry_delay, retry_on


def _validate_precondition_fields(prefix: str, pre_norm: dict, idx: int, total_steps: int, errors: list) -> None:
    if not pre_norm["result_key"]:
        errors.append(f"{prefix}: precondition requires result_key")
    if pre_norm["operator"] not in CONDITION_OPERATORS:
        errors.append(
            f"{prefix}: precondition operator must be one of {sorted(CONDITION_OPERATORS)}"
        )
    if pre_norm["step"] is not None:
        if pre_norm["step"] < 1 or pre_norm["step"] > total_steps:
            errors.append(f"{prefix}: precondition.step out of range")
        elif pre_norm["step"] == idx + 1:
            errors.append(f"{prefix}: precondition cannot reference its own step")


def _validate_step_deps_retry(prefix: str, step, idx: int, total_steps: int, errors: list) -> tuple[list[int], int, int, list[str], dict | None]:
    depends_on_norm = _validate_dep_values(prefix, step.depends_on, idx, total_steps, errors)
    retry_count, retry_delay, retry_on = _validate_retry_config(prefix, step, errors)
    pre_norm = _normalize_precondition(step.precondition) if step.precondition else None
    if pre_norm is not None:
        _validate_precondition_fields(prefix, pre_norm, idx, total_steps, errors)
    return depends_on_norm, retry_count, retry_delay, retry_on, pre_norm


def _validate_dag_constraints(normalized_steps: list, total_steps: int, errors: list, warnings: list) -> None:
    adj = {
        i: [d - 1 for d in (s.get("depends_on") or []) if 1 <= d <= total_steps]
        for i, s in enumerate(normalized_steps)
    }
    cycle = _detect_cycle(adj, total_steps)
    if cycle:
        errors.append(
            "Dependency graph contains a cycle: " + " → ".join(f"#{i + 1}" for i in cycle)
        )
    for i, s in enumerate(normalized_steps):
        if s.get("on_success") == "jump" or s.get("on_failure") == "jump":
            errors.append(
                f"Step {i + 1}: 'jump' branching is not allowed in DAG mode "
                "(remove depends_on / retry_count / precondition or remove the jump)"
            )
        pre = s.get("precondition") or {}
        ref = pre.get("step")
        deps = s.get("depends_on") or []
        if ref is not None and (ref not in deps):
            warnings.append(
                f"Step {i + 1}: precondition references step #{ref} which is not "
                "listed in depends_on — its result may not be ready when this step runs"
            )


def _condition_rule_applies(rule: dict, status: str) -> bool:
    if rule["when"] not in {"success", "failure", "always"}:
        return False
    if rule["when"] == "success" and status != "done":
        return False
    if rule["when"] == "failure" and status == "done":
        return False
    return True


def _resolve_matched_action(rule: dict, total_steps: int):
    if rule["action"] == "stop":
        return None, True
    if rule["action"] == "jump":
        target = rule.get("target_step")
        if isinstance(target, int) and 1 <= target <= total_steps:
            return target - 1, False
        return None, True
    return None, False


def _resolve_result_condition_target(
    step: dict, job_result: dict, *, status: str, total_steps: int
):
    for raw_rule in step.get("result_conditions") or []:
        rule = _normalize_condition(raw_rule)
        if not _condition_rule_applies(rule, status):
            continue
        actual = _extract_result_value(job_result or {}, rule["result_key"])
        if _condition_matches(actual, rule["operator"], rule["value"]):
            return _resolve_matched_action(rule, total_steps)
    return None, False


def _validate_playbook_payload(body: PlaybookBody, available_connectors: list[dict]) -> dict:
    errors = []
    warnings = []
    connector_map = {item["key"]: item for item in available_connectors}

    if not body.title.strip():
        errors.append("Title is required")
    if not body.steps:
        errors.append("At least one step is required")

    normalized_steps = []
    total_steps = len(body.steps)
    for idx, step in enumerate(body.steps):
        prefix = f"Step {idx + 1}"
        if not step.title.strip():
            errors.append(f"{prefix}: title is required")
        connector = connector_map.get(step.connector_key)
        if not connector:
            errors.append(f"{prefix}: unsupported connector {step.connector_key!r}")
            continue
        if step.operation not in (connector.get("supported_operations") or []):
            errors.append(
                f"{prefix}: unsupported operation {step.operation!r} for connector {step.connector_key!r}"
            )
            continue
        on_success, on_failure = _validate_step_branching(prefix, step, total_steps, errors)
        normalized_conditions = _validate_step_conditions(prefix, step, total_steps, errors)
        params = dict(step.params or {})
        params = _validate_step_params(prefix, step, params, errors, warnings)
        depends_on_norm, retry_count, retry_delay, retry_on, pre_norm = _validate_step_deps_retry(
            prefix, step, idx, total_steps, errors
        )
        normalized_steps.append(
            {
                "title": step.title.strip(),
                "connector_key": step.connector_key,
                "operation": step.operation,
                "params": params,
                "on_success": on_success,
                "on_success_step": step.on_success_step,
                "on_failure": on_failure,
                "on_failure_step": step.on_failure_step,
                "result_conditions": normalized_conditions,
                "depends_on": depends_on_norm,
                "retry_count": retry_count,
                "retry_delay_seconds": retry_delay,
                "retry_on": retry_on,
                "precondition": pre_norm,
            }
        )

    if _is_dag_mode(normalized_steps):
        _validate_dag_constraints(normalized_steps, total_steps, errors, warnings)

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "normalized": {
            "title": body.title.strip(),
            "description": body.description.strip(),
            "steps": normalized_steps,
        },
    }
