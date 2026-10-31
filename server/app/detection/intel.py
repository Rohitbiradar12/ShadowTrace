"""Local indicator lists and allowlists; no external feeds are needed for the MVP."""

import ipaddress
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field


class IndicatorList(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["domain", "ip", "sha256", "text", "path", "url"]
    values: list[str] = Field(default_factory=list)


def _domain(value: str) -> str:
    return value.strip().rstrip(".").encode("idna").decode("ascii").lower()


class IntelLists:
    def __init__(self, definitions: dict[str, IndicatorList]):
        self.definitions = definitions
        self.values: dict[str, set] = {}
        for name, entry in definitions.items():
            self.values[name] = {self._normalize(entry.kind, v) for v in entry.values}

    @staticmethod
    def _normalize(kind: str, value: str) -> Any:
        if kind == "domain":
            return _domain(value)
        if kind == "ip":
            return ipaddress.ip_network(value, strict=False)
        if kind == "sha256":
            value = value.strip().lower()
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError(f"Invalid SHA-256 indicator: {value!r}")
            return value
        if kind == "path":
            return value.replace("\\", "/").rstrip("/").casefold()
        if kind == "url":
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.hostname:
                raise ValueError(f"Invalid URL indicator: {value!r}")
            return value
        return value

    def contains(self, name: str, value: Any) -> bool:
        if name not in self.definitions:
            raise ValueError(f"Unknown indicator list: {name}")
        if not isinstance(value, str):
            return False
        kind = self.definitions[name].kind
        try:
            normalized = self._normalize(kind, value)
        except (ValueError, UnicodeError):
            return False
        entries = self.values[name]
        if kind == "domain":
            return any(normalized == d or normalized.endswith("." + d) for d in entries)
        if kind == "ip":
            return any(normalized.version == n.version and normalized.subnet_of(n) for n in entries)
        if kind == "path":
            return any(normalized == p or normalized.startswith(p + "/") for p in entries)
        return normalized in entries


def load_intel(path: Path) -> IntelLists:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Indicator file must map list names to definitions")
    return IntelLists({name: IndicatorList.model_validate(value) for name, value in raw.items()})
