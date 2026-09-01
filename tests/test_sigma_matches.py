"""Behavioural proof: each Sigma rule fires on malicious samples, not benign ones."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from detlib import load_sigma_rule

REPO = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO / "rules" / "sigma"
SAMPLES = REPO / "samples"

# rule file -> (malicious samples, benign samples)
CASES = {
    "llm_prompt_injection_indicators.yml": (
        "prompt_injection_malicious.jsonl",
        "prompt_injection_benign.jsonl",
    ),
    "llm_jailbreak_signatures.yml": (
        "jailbreak_malicious.jsonl",
        "jailbreak_benign.jsonl",
    ),
    "llm_many_shot_scaffolding.yml": (
        "many_shot_malicious.jsonl",
        "many_shot_benign.jsonl",
    ),
}


def _load_events(name: str) -> list[dict]:
    lines = (SAMPLES / name).read_text().strip().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.mark.parametrize("rule_file,samples", CASES.items(), ids=list(CASES))
def test_malicious_samples_match(rule_file: str, samples: tuple[str, str]):
    rule = load_sigma_rule(SIGMA_DIR / rule_file)
    malicious, _ = samples
    events = _load_events(malicious)
    assert events, f"no malicious samples for {rule_file}"
    for event in events:
        assert rule.matches(event), f"{rule_file} failed to match malicious: {event['prompt']!r}"


@pytest.mark.parametrize("rule_file,samples", CASES.items(), ids=list(CASES))
def test_benign_samples_do_not_match(rule_file: str, samples: tuple[str, str]):
    rule = load_sigma_rule(SIGMA_DIR / rule_file)
    _, benign = samples
    events = _load_events(benign)
    assert events, f"no benign samples for {rule_file}"
    for event in events:
        assert not rule.matches(event), (
            f"{rule_file} false-positived on benign: {event['prompt']!r}"
        )
