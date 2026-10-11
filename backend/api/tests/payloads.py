"""Build GitHub API response payloads that satisfy `githubkit`'s own schemas.

`githubkit` validates every response body against a generated Pydantic model. That is a feature —
it is how a changed API surfaces as an error rather than as a silently missing field — but it means
a hand-written fixture has to carry every required field, and `Repository` alone has more than
forty.

So the fixtures are generated from the schema instead: `payload_for(Model, **overrides)` fills each
required field with a value of the right type and lets the test state only the parts it cares
about. When githubkit's schemas move, the fixtures move with them, which is the whole point of
testing against the real client rather than a hand-rolled mock.
"""

from __future__ import annotations

import types
import typing
from datetime import UTC, datetime
from typing import Any, Literal, get_args, get_origin

from pydantic import BaseModel

_TIMESTAMP = datetime(2026, 1, 1, tzinfo=UTC).isoformat()


def _value_for(annotation: Any) -> Any:
    """A plausible value for one annotated field."""
    origin = get_origin(annotation)

    if origin is Literal:
        return get_args(annotation)[0]

    if origin in (typing.Union, types.UnionType):
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        # Optional fields are satisfied by null, which is also the least presumptuous answer for a
        # field the code under test does not read.
        if len(args) < len(get_args(annotation)):
            return None
        return _value_for(args[0])

    if origin in (list, set, tuple):
        return []
    if origin is dict:
        return {}

    if isinstance(annotation, type):
        if issubclass(annotation, BaseModel):
            return payload_for(annotation)
        if issubclass(annotation, bool):
            return False
        if issubclass(annotation, int):
            return 1
        if issubclass(annotation, float):
            return 1.0
        if issubclass(annotation, datetime):
            return _TIMESTAMP
        if issubclass(annotation, str):
            return "x"

    return None


def payload_for(model: type[BaseModel], **overrides: Any) -> dict[str, Any]:
    """A dict that validates as `model`, with `overrides` applied by field name.

    Overrides use the model's field names; `githubkit` aliases a few (`license_`), and the alias is
    resolved here so tests can name fields the way the API does.
    """
    payload: dict[str, Any] = {}
    for name, field in model.model_fields.items():
        key = field.alias or name
        if not field.is_required():
            continue
        payload[key] = _value_for(field.annotation)

    for name, value in overrides.items():
        field = model.model_fields.get(name)
        payload[field.alias or name if field else name] = value
    return payload
