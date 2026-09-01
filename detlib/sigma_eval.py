"""A deliberately small Sigma evaluator.

This is not a full Sigma engine. It supports exactly the subset of Sigma used by
the rules in this repo, so the test suite can prove each rule fires on its
malicious sample events and stays quiet on the benign ones:

* named selections whose keys are ANDed together;
* the ``|contains`` field modifier (case-insensitive substring match);
* the ``|gt`` / ``|gte`` / ``|lt`` / ``|lte`` numeric modifiers, so structural
  rules can compare counts and sizes rather than matching vocabulary;
* plain equality (case-insensitive) when no modifier is given;
* list values, treated as OR within a single field;
* a ``condition`` built from selection names, ``and`` / ``or`` / ``not`` and
  parentheses.

Anything outside that subset raises, rather than silently returning the wrong
answer, so the rules can't drift away from what the evaluator actually checks.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_NUMERIC_OPS = {
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
}
_NUMERIC_MODIFIERS = frozenset(_NUMERIC_OPS)
_SUPPORTED_MODIFIERS = _NUMERIC_MODIFIERS | {"contains"}

_TOKEN_RE = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*)")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _match_field(event: dict[str, Any], field_expr: str, values: Any) -> bool:
    field, *modifiers = field_expr.split("|")
    raw = event.get(field)
    if raw is None:
        return False
    haystack = str(raw)
    candidates = [str(v) for v in _as_list(values)]

    unknown = set(modifiers) - _SUPPORTED_MODIFIERS
    if unknown:
        raise ValueError(f"unsupported Sigma modifier(s): {sorted(unknown)}")

    numeric = set(modifiers) & _NUMERIC_MODIFIERS
    if numeric:
        if len(numeric) > 1:
            raise ValueError(f"conflicting numeric modifiers: {sorted(numeric)}")
        return _match_numeric(raw, numeric.pop(), _as_list(values), field)

    if "contains" in modifiers:
        haystack_lower = haystack.lower()
        return any(v.lower() in haystack_lower for v in candidates)
    return any(haystack.lower() == v.lower() for v in candidates)


def _match_numeric(raw: Any, modifier: str, values: list[Any], field: str) -> bool:
    """Structural rules compare counts and sizes, not substrings.

    A field that is absent has already been handled by the caller. A field that is
    present but not numeric is a schema error in the event, not a non-match, so it
    raises rather than silently failing closed and hiding the bad data.
    """
    try:
        observed = float(raw)
    except (TypeError, ValueError):
        raise ValueError(
            f"field {field!r} must be numeric for the {modifier!r} modifier, got {raw!r}"
        ) from None
    op = _NUMERIC_OPS[modifier]
    return any(op(observed, float(v)) for v in values)


def _match_selection(event: dict[str, Any], selection: Any) -> bool:
    if isinstance(selection, list):
        return any(_match_selection(event, item) for item in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, fe, vals) for fe, vals in selection.items())
    raise ValueError(f"unsupported selection shape: {type(selection).__name__}")


class _ConditionParser:
    """Recursive-descent parser for the boolean subset of Sigma conditions."""

    def __init__(self, condition: str, selections: dict[str, Any], event: dict[str, Any]):
        self._tokens = self._tokenize(condition)
        self._pos = 0
        self._selections = selections
        self._event = event

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        # A condition written as a folded or literal YAML scalar arrives with
        # newlines and trailing whitespace. That is valid Sigma, so normalise it
        # rather than refusing to parse a rule that other engines accept.
        condition = " ".join(condition.split())
        tokens: list[str] = []
        pos = 0
        while pos < len(condition):
            match = _TOKEN_RE.match(condition, pos)
            if not match:
                raise ValueError(f"cannot tokenize condition near: {condition[pos:]!r}")
            tokens.append(match.group(1))
            pos = match.end()
        return tokens

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str:
        token = self._tokens[self._pos]
        self._pos += 1
        return token

    def evaluate(self) -> bool:
        result = self._expr()
        if self._pos != len(self._tokens):
            raise ValueError("trailing tokens in condition")
        return result

    def _expr(self) -> bool:
        value = self._term()
        while self._peek() == "or":
            self._next()
            value = self._term() or value
        return value

    def _term(self) -> bool:
        value = self._factor()
        while self._peek() == "and":
            self._next()
            value = self._factor() and value
        return value

    def _factor(self) -> bool:
        token = self._peek()
        if token == "not":
            self._next()
            return not self._factor()
        if token == "(":
            self._next()
            value = self._expr()
            if self._next() != ")":
                raise ValueError("unbalanced parentheses in condition")
            return value
        if token is None or token in {"and", "or", ")"}:
            raise ValueError("unexpected end of condition")
        name = self._next()
        if name not in self._selections:
            raise ValueError(f"condition references unknown selection: {name!r}")
        return _match_selection(self._event, self._selections[name])


@dataclass
class SigmaRule:
    title: str
    condition: str
    selections: dict[str, Any]
    raw: dict[str, Any]

    def matches(self, event: dict[str, Any]) -> bool:
        return _ConditionParser(self.condition, self.selections, event).evaluate()


def load_sigma_rule(path: str | Path) -> SigmaRule:
    data = yaml.safe_load(Path(path).read_text())
    detection = data["detection"]
    condition = detection["condition"]
    selections = {k: v for k, v in detection.items() if k != "condition"}
    return SigmaRule(
        title=data["title"],
        condition=condition,
        selections=selections,
        raw=data,
    )
