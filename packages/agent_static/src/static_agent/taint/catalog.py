"""Rule catalog loader for sources, sinks, and sanitizers."""

import re
from pathlib import Path
from typing import Any, Dict, List
import yaml
from pydantic import BaseModel, ConfigDict, Field


class RuleSource(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    match: str
    cwe_hint: str = "injection"


class RuleSink(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    match: str
    cwe: str
    danger: str = "high"
    requires_arg: str = ""
    forbids_arg: str = ""


class RuleSanitizer(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    match: str
    clears: List[str] = Field(default_factory=list)


class Catalog(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sources: Dict[str, List[RuleSource]] = Field(default_factory=dict)
    sinks: Dict[str, List[RuleSink]] = Field(default_factory=dict)
    sanitizers: Dict[str, List[RuleSanitizer]] = Field(default_factory=dict)

    @classmethod
    def load_from_dir(cls, rules_dir: Path) -> "Catalog":
        """Load YAML rule files from directory with defensive error handling."""
        sources_path = rules_dir / "sources.yml"
        sinks_path = rules_dir / "sinks.yml"
        sanitizers_path = rules_dir / "sanitizers.yml"

        def _load_yaml(path: Path) -> Dict[str, Any]:
            if not path.exists():
                return {}
            try:
                content = path.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}

        def _parse_rules(raw_dict: Dict[str, Any], model_cls: Any) -> Dict[str, List[Any]]:
            parsed: Dict[str, List[Any]] = {}
            for lang, items in raw_dict.items():
                if not isinstance(items, list):
                    continue
                parsed_items = []
                for item in items:
                    if isinstance(item, dict):
                        try:
                            parsed_items.append(model_cls(**item))
                        except Exception:
                            continue
                parsed[lang] = parsed_items
            return parsed

        sources = _parse_rules(_load_yaml(sources_path), RuleSource)
        sinks = _parse_rules(_load_yaml(sinks_path), RuleSink)
        sanitizers = _parse_rules(_load_yaml(sanitizers_path), RuleSanitizer)

        return cls(sources=sources, sinks=sinks, sanitizers=sanitizers)

    def matches_pattern(self, pattern: str, text: str) -> bool:
        """Check if regex pattern matches target text."""
        if not pattern or not text:
            return False
        try:
            return bool(re.search(pattern, text))
        except re.error:
            return False

