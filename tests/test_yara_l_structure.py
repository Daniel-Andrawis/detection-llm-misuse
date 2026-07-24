"""Structural checks for the YARA-L rules.

No local YARA-L engine ships with SecOps, so these are structural rather than
behavioural: they confirm each rule declares the blocks and metadata a reviewer
(and the SecOps compiler) expects, and that correlation rules define a match
window.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
YARA_L_DIR = REPO / "rules" / "yara-l"

YARA_L_FILES = sorted(YARA_L_DIR.glob("*.yaml"))


def test_yara_l_rules_exist():
    assert YARA_L_FILES, "expected at least one YARA-L rule"


@pytest.mark.parametrize("path", YARA_L_FILES, ids=lambda p: p.name)
def test_yara_l_structure(path: Path):
    text = path.read_text()

    for block in ("meta:", "events:", "match:", "condition:"):
        assert block in text, f"{path.name} missing required block: {block}"

    for key in ("author", "description", "severity", "mitre_atlas"):
        assert key in text, f"{path.name} meta missing: {key}"

    assert text.count("rule ") >= 1, f"{path.name} has no rule declaration"
    assert text.count("{") == text.count("}"), f"{path.name} has unbalanced braces"
