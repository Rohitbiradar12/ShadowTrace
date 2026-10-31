"""Matching an event against a rule's conditions.

A condition block is a mapping of ``field -> matcher`` where every entry must hold (AND). A
field is a dotted path into the event (``action``, ``data.target_user``, ``data.parent.name``).
A matcher is either a bare value (equality) or ``{operator: operand}``. Intel-list lookups
(``in_list``) are resolved through an optional resolver so this module stays free of I/O.

Pure and side-effect free, so the whole operator surface is unit-tested directly.
"""

import re
from collections.abc import Callable
from typing import Any

MISSING = object()
OPERATORS = {
    "eq",
    "ne",
    "in",
    "not_in",
    "exists",
    "gt",
    "ge",
    "lt",
    "le",
    "contains",
    "icontains",
    "contains_any",
    "icontains_any",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
    "regex",
    "iregex",
    "in_list",
    "not_in_list",
}

IntelResolver = Callable[[str, Any], bool]


def get_field(event: dict[str, Any], path: str) -> Any:
    value: Any = event
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return MISSING
    return value


def _as_list(operand: Any) -> list:
    return operand if isinstance(operand, list) else [operand]


def _cmp(value: Any, operand: Any, op: Callable[[Any, Any], bool]) -> bool:
    try:
        return op(value, operand)
    except TypeError:
        return False


def apply_operator(op: str, value: Any, operand: Any, intel: IntelResolver | None) -> bool:
    if op not in OPERATORS:
        raise ValueError(f"Unknown condition operator: {op!r}")
    present = value is not MISSING
    match op:
        case "eq":
            return present and value == operand
        case "ne":
            return value != operand  # a missing field is "not equal"
        case "in":
            return present and value in _as_list(operand)
        case "not_in":
            return not (present and value in _as_list(operand))
        case "exists":
            return present is bool(operand)
        case "gt" | "ge" | "lt" | "le":
            if not present:
                return False
            ops = {
                "gt": lambda a, b: a > b,
                "ge": lambda a, b: a >= b,
                "lt": lambda a, b: a < b,
                "le": lambda a, b: a <= b,
            }
            return _cmp(value, operand, ops[op])
        case _ if not present or value is None:
            return False
        case "contains":
            return isinstance(value, str) and str(operand) in value
        case "icontains":
            return isinstance(value, str) and str(operand).lower() in value.lower()
        case "contains_any":
            return isinstance(value, str) and any(str(o) in value for o in _as_list(operand))
        case "icontains_any":
            low = value.lower() if isinstance(value, str) else ""
            return isinstance(value, str) and any(str(o).lower() in low for o in _as_list(operand))
        case "startswith":
            return isinstance(value, str) and value.startswith(tuple(_as_list(operand)))
        case "istartswith":
            return isinstance(value, str) and value.lower().startswith(
                tuple(str(o).lower() for o in _as_list(operand))
            )
        case "endswith":
            return isinstance(value, str) and value.endswith(tuple(_as_list(operand)))
        case "iendswith":
            return isinstance(value, str) and value.lower().endswith(
                tuple(str(o).lower() for o in _as_list(operand))
            )
        case "regex":
            return isinstance(value, str) and re.search(str(operand), value) is not None
        case "iregex":
            return (
                isinstance(value, str) and re.search(str(operand), value, re.IGNORECASE) is not None
            )
        case "in_list" | "not_in_list":
            if intel is None:
                return False
            matched = intel(str(operand), value)
            return matched if op == "in_list" else not matched
        case _:
            raise ValueError(f"Unknown condition operator: {op!r}")


def match_field(value: Any, matcher: Any, intel: IntelResolver | None) -> bool:
    if isinstance(matcher, dict):
        return all(apply_operator(op, value, operand, intel) for op, operand in matcher.items())
    # Bare value: equality, with a missing field never matching.
    return value is not MISSING and value == matcher


def match_conditions(
    event: dict[str, Any], conditions: dict[str, Any], intel: IntelResolver | None = None
) -> bool:
    return all(
        match_field(get_field(event, field), matcher, intel)
        for field, matcher in conditions.items()
    )


def validate_conditions(conditions: dict[str, Any]) -> dict[str, Any]:
    """Reject invalid rules at load time, even if their fields never occur in events."""
    if not conditions:
        raise ValueError("A condition block must not be empty")
    for path, matcher in conditions.items():
        if not re.fullmatch(r"[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*", path):
            raise ValueError(f"Invalid field path: {path!r}")
        if not isinstance(matcher, dict):
            continue
        if not matcher:
            raise ValueError(f"Empty matcher for {path}")
        for op, operand in matcher.items():
            if op not in OPERATORS:
                raise ValueError(f"Unknown condition operator: {op!r}")
            if op in {"regex", "iregex"}:
                try:
                    re.compile(operand)
                except (TypeError, re.error) as exc:
                    raise ValueError(f"Invalid regex for {path}: {exc}") from exc
            if op == "exists" and not isinstance(operand, bool):
                raise ValueError("exists requires a boolean")
            if op in {"in_list", "not_in_list"} and not isinstance(operand, str):
                raise ValueError(f"{op} requires a list name")
            if op in {"startswith", "endswith", "istartswith", "iendswith"}:
                if not all(isinstance(v, str) for v in _as_list(operand)):
                    raise ValueError(f"{op} requires strings")
    return conditions
