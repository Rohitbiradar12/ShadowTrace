"""Rules evaluated against stored events, with event-time threshold windows.

MongoDB supplies the window, so restarts and offline uploads do not discard correlation
state. Only events at or before the current ingestion index participate in a firing.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

from app.core.config import get_settings
from app.detection.conditions import MISSING, get_field, match_conditions
from app.detection.intel import IntelLists, load_intel
from app.detection.rules import Rule, load_rules
from app.models import Event


@dataclass
class Match:
    rule: Rule
    group: dict[str, Any]
    event_ids: list[str]
    first_at: datetime
    last_at: datetime


class DetectionEngine:
    def __init__(self, rules: list[Rule], intel: IntelLists):
        self.rules = [rule for rule in rules if rule.enabled]
        self.intel = intel
        for rule in rules:
            for block in [rule.match, *rule.exclude]:
                for matcher in block.values():
                    if isinstance(matcher, dict):
                        for op, operand in matcher.items():
                            if (
                                op in {"in_list", "not_in_list"}
                                and operand not in intel.definitions
                            ):
                                raise ValueError(
                                    f"Rule {rule.id} references unknown list {operand}"
                                )

    def matches(self, rule: Rule, event: dict) -> bool:
        return (
            (rule.category is None or rule.category == event["category"])
            and match_conditions(event, rule.match, self.intel.contains)
            and not any(
                match_conditions(event, block, self.intel.contains) for block in rule.exclude
            )
        )

    async def evaluate(self, event: dict) -> list[Match]:
        matches = []
        for rule in self.rules:
            if not self.matches(rule, event):
                continue
            if rule.threshold is None:
                matches.append(Match(rule, {}, [event["event_id"]], event["ts"], event["ts"]))
                continue
            group = {path: get_field(event, path) for path in rule.threshold.group_by}
            if any(value is MISSING or value is None for value in group.values()):
                continue
            evidence = await self._threshold_window(rule, event, group)
            if evidence:
                ids = list(
                    dict.fromkeys([e["event_id"] for e in evidence][-99:] + [event["event_id"]])
                )
                matches.append(Match(rule, group, ids, evidence[0]["ts"], evidence[-1]["ts"]))
        return matches

    async def _threshold_window(self, rule: Rule, event: dict, group: dict) -> list[dict]:
        threshold = rule.threshold
        window = timedelta(seconds=threshold.window_seconds)
        query = {
            "device_id": event["device_id"],
            "chain_index": {"$lte": event["chain_index"]},
            # Look on both sides to handle events that arrive out of timestamp order.
            "ts": {"$gte": event["ts"] - window, "$lte": event["ts"] + window},
            "$and": [{path: {"$eq": value}} for path, value in group.items()],
        }
        if rule.category:
            query["category"] = rule.category
        for field in ("category", "action"):
            if isinstance(rule.match.get(field), str):
                query[field] = rule.match[field]
        cursor = Event.get_pymongo_collection().find(query).sort([("ts", 1), ("chain_index", 1)])
        candidates = [row async for row in cursor if self.matches(rule, row)]
        trigger_index = next(
            (i for i, row in enumerate(candidates) if row["event_id"] == event["event_id"]), -1
        )
        left = 0
        for right, row in enumerate(candidates):
            while row["ts"] - candidates[left]["ts"] > window:
                left += 1
            if left <= trigger_index <= right and right - left + 1 >= threshold.count:
                return candidates[left : right + 1]
        return []


@lru_cache
def get_engine() -> DetectionEngine:
    settings = get_settings()
    return DetectionEngine(load_rules(settings.rules_dir), load_intel(settings.intel_file))
