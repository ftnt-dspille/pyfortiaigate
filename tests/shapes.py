"""Check a response against its declared TypedDict: every key the appliance
sent must be declared (recursively), so the documented fields stay complete."""

from __future__ import annotations

import types
import typing
from typing import Any


def undeclared(value: Any, tp: Any, path: str = "$") -> list[str]:
    """Paths of keys in ``value`` that ``tp`` does not declare."""
    if value is None or tp is Any:
        return []
    origin = typing.get_origin(tp)
    if origin in (typing.Union, types.UnionType):
        options = [a for a in typing.get_args(tp) if a is not type(None)]
        found = [undeclared(value, a, path) for a in options]
        return min(found, key=len) if found else []
    if origin in (list, typing.get_origin(typing.Iterator[int])) and isinstance(value, list):
        (inner,) = typing.get_args(tp) or (Any,)
        return [p for i, v in enumerate(value) for p in undeclared(v, inner, f"{path}[{i}]")]
    if typing.is_typeddict(tp) and isinstance(value, dict):
        hints = typing.get_type_hints(tp)
        out = [f"{path}.{k}" for k in value if k not in hints]
        for k, v in value.items():
            if k in hints:
                out += undeclared(v, hints[k], f"{path}.{k}")
        return out
    return []


def assert_declared(value: Any, tp: Any) -> None:
    missing = undeclared(value, tp)
    # one example per distinct path shape, so a long list does not flood the message
    shapes = sorted({_generic(p) for p in missing})
    assert not shapes, f"fields not declared in {_name(tp)}: {shapes}"


def _generic(path: str) -> str:
    import re

    return re.sub(r"\[\d+\]", "[]", path)


def _name(tp: Any) -> str:
    return tp.__name__ if isinstance(tp, type) and typing.is_typeddict(tp) else str(tp)
