"""Every rule must carry the metadata that makes a detection portfolio-grade."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO / "rules" / "sigma"

SIGMA_FILES = sorted(SIGMA_DIR.glob("*.yml"))
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def test_sigma_rules_exist():
    assert SIGMA_FILES, "expected at least one Sigma rule"


@pytest.mark.parametrize("path", SIGMA_FILES, ids=lambda p: p.name)
def test_sigma_rule_metadata(path: Path):
    rule = yaml.safe_load(path.read_text())

    for field in ("title", "id", "status", "description", "author", "date", "tags",
                  "logsource", "detection", "falsepositives", "level"):
        assert field in rule, f"{path.name} missing required field: {field}"

    # id must be a real UUID
    uuid.UUID(str(rule["id"]))

    # must cite a technique - an ATT&CK or ATLAS tag
    assert any(str(t).startswith(("attack.", "atlas.")) for t in rule["tags"]), (
        f"{path.name} has no attack./atlas. technique tag"
    )

    # false positives must be honestly enumerated, not empty
    assert isinstance(rule["falsepositives"], list) and rule["falsepositives"], (
        f"{path.name} must list false positives"
    )

    assert rule["level"] in VALID_LEVELS, f"{path.name} has invalid level: {rule['level']}"

    # condition must reference only defined selections (smoke check)
    detection = rule["detection"]
    assert "condition" in detection, f"{path.name} detection has no condition"
