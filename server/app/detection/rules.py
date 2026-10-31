"""Detection rule definitions and YAML loading.

A rule matches events and raises an alert. Without a ``threshold`` block it is a single-event
rule (one matching event fires). With one, it fires only when ``count`` matching events share
the same ``group_by`` values within ``window_seconds`` — how brute force and mass-copy are
detected.
"""

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.conditions import validate_conditions

Severity = Literal["low", "medium", "high", "critical"]
AutoAction = Literal["lock_workstation", "kill_process"]


class Threshold(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int = Field(ge=2, le=10000)
    window_seconds: float = Field(gt=0, le=86400)
    group_by: list[str] = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _parse_within(cls, value):
        if isinstance(value, dict) and "within" in value:
            value = dict(value)
            within = value.pop("within")
            if "window_seconds" in value:
                raise ValueError("Use either within or window_seconds")
            match = re.fullmatch(r"(\d+(?:\.\d+)?)(s|m|h)", str(within))
            if not match:
                raise ValueError("within must be a duration such as 120s, 5m or 1h")
            value["window_seconds"] = float(match[1]) * {"s": 1, "m": 60, "h": 3600}[match[2]]
        return value

    @field_validator("group_by")
    @classmethod
    def _valid_groups(cls, value):
        validate_conditions(dict.fromkeys(value, {"exists": True}))
        return value


class Response(BaseModel):
    model_config = ConfigDict(extra="forbid")
    notify: list[Literal["telegram", "email"]] | None = None  # None = use severity defaults
    auto_action: AutoAction | None = None


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{1,40}$")
    title: str
    description: str = ""
    severity: Severity = "medium"
    mitre: list[str] = Field(default_factory=list)
    enabled: bool = True
    # Optional fast pre-filter; the engine groups rules by category to skip non-matches.
    category: str | None = None
    match: dict[str, Any]
    exclude: list[dict[str, Any]] = Field(default_factory=list)
    threshold: Threshold | None = None
    response: Response = Field(default_factory=Response)

    @field_validator("match")
    @classmethod
    def _match_not_empty(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_conditions(value)

    @field_validator("exclude")
    @classmethod
    def _valid_exclusions(cls, value):
        return [validate_conditions(block) for block in value]

    @property
    def is_threshold(self) -> bool:
        return self.threshold is not None


def load_rule_file(path: Path) -> Rule:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Rule.model_validate(data)


def load_rules(directory: Path) -> list[Rule]:
    """Load and validate every ``*.yaml`` rule in a directory. Duplicate ids are rejected."""
    if not directory.is_dir():
        raise ValueError(f"Rules directory does not exist: {directory}")
    rules: dict[str, Rule] = {}
    for path in sorted(directory.glob("*.yaml")):
        rule = load_rule_file(path)
        if rule.id in rules:
            raise ValueError(f"Duplicate rule id {rule.id!r} in {path.name}")
        rules[rule.id] = rule
    return list(rules.values())
