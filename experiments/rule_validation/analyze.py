"""Summarise a rule-validation research log.

Reports, per selection, how often the scaffold changed the outcome versus the
unwrapped control. Read the interpretation caveat in README.md before drawing a
conclusion from these numbers.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


def load(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    runs, trials = [], []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            (runs if record.get("record_type") == "run" else trials).append(record)
    return runs, trials


def refusal_category(trial: dict[str, Any]) -> str | None:
    details = trial.get("stop_details")
    if isinstance(details, dict):
        return details.get("category") or "unspecified"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument(
        "--show-refusals",
        action="store_true",
        help="print the prompt and response for every refusal",
    )
    args = parser.parse_args()

    runs, trials = load(args.log)
    if not trials:
        print("No trial records in log.")
        return 1

    print("=" * 72)
    print("RULE VALIDATION SUMMARY")
    print("=" * 72)
    for run in runs:
        print(f"run          {run.get('started_at')}")
        print(f"  requested  {run.get('model_requested')}")
        print(f"  rule       {run.get('rule_path')} (id {run.get('rule_id')})")
        print(f"  sdk        {run.get('sdk_version')}")

    served = sorted({t["model_returned"] for t in trials if t.get("model_returned")})
    errors = [t for t in trials if t.get("error")]
    print(f"\nserved by    {', '.join(served) if served else 'n/a'}")
    print(f"trials       {len(trials)}   errors: {len(errors)}")

    if errors:
        print("\nERRORS (first 5):")
        for trial in errors[:5]:
            print(f"  [{trial['selection']}] {trial['error']}")

    ok = [t for t in trials if not t.get("error")]
    if not ok:
        print("\nEvery call errored - nothing to compare.")
        return 1

    # Control baseline, per target, so each scaffold is compared against the same ask.
    control_chars: dict[str, list[int]] = defaultdict(list)
    control_refusals = 0
    control_n = 0
    for trial in ok:
        if trial["selection"] == "control":
            control_chars[trial["target"]].append(trial["response_chars"])
            control_n += 1
            if trial["stop_reason"] == "refusal":
                control_refusals += 1

    # A response clipped at max_tokens reports a length floor, not a length. Comparing
    # those against controls yields a delta that is an artefact of the ceiling, so the
    # length column is suppressed whenever truncation is more than incidental. Refusal
    # rates survive truncation untouched: a refusal reports stop_reason "refusal"
    # whatever the budget was.
    truncated = [t for t in ok if t["stop_reason"] == "max_tokens"]
    truncation_rate = len(truncated) / len(ok)
    length_reliable = truncation_rate <= 0.10

    print("\n" + "-" * 72)
    print(f"{'selection':<22}{'n':>4}{'refused':>9}{'rate':>8}{'len vs control':>17}")
    print("-" * 72)

    if control_n:
        print(
            f"{'control':<22}{control_n:>4}{control_refusals:>9}"
            f"{control_refusals / control_n:>8.0%}{'--':>17}"
        )

    by_selection: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trial in ok:
        if trial["selection"] != "control":
            by_selection[trial["selection"]].append(trial)

    categories: dict[str, set[str]] = defaultdict(set)
    for selection, group in sorted(by_selection.items()):
        refused = [t for t in group if t["stop_reason"] == "refusal"]
        for trial in refused:
            category = refusal_category(trial)
            if category:
                categories[selection].add(category)

        deltas = []
        for trial in group:
            baseline = control_chars.get(trial["target"])
            if baseline:
                deltas.append(trial["response_chars"] - statistics.mean(baseline))
        if not length_reliable:
            delta = "suppressed"
        else:
            delta = f"{statistics.mean(deltas):+.0f} chars" if deltas else "n/a"

        print(
            f"{selection:<22}{len(group):>4}{len(refused):>9}"
            f"{len(refused) / len(group):>8.0%}{delta:>17}"
        )

    if truncated:
        print(
            f"\nNOTE: {len(truncated)}/{len(ok)} responses stopped at max_tokens "
            f"({truncation_rate:.0%})."
        )
        if not length_reliable:
            print(
                "  Length deltas are SUPPRESSED. A truncated response measures the token\n"
                "  ceiling, not the model's behaviour, so the comparison would be an\n"
                "  artefact. Re-run with a larger --max-tokens. Refusal rates are\n"
                "  unaffected and remain readable."
            )

    if categories:
        print("\nrefusal categories reported by the API:")
        for selection, cats in sorted(categories.items()):
            print(f"  {selection:<22}{', '.join(sorted(cats))}")

    stop_reasons: dict[str, int] = defaultdict(int)
    for trial in ok:
        stop_reasons[str(trial["stop_reason"])] += 1
    print("\nstop_reason distribution:")
    for reason, count in sorted(stop_reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {reason:<22}{count}")

    if args.show_refusals:
        refusals = [t for t in ok if t["stop_reason"] == "refusal"]
        print(f"\n{'=' * 72}\nREFUSALS ({len(refusals)})\n{'=' * 72}")
        for trial in refusals:
            print(f"\n[{trial['selection']}] {trial['prompt']!r}")
            print(f"  category: {refusal_category(trial)}")
            if trial["response_text"]:
                print(f"  response: {trial['response_text'][:200]}")

    print(
        "\nReminder: a refusal on a BENIGN request means the model read the framing as "
        "adversarial.\nThat is not evidence the scaffold works. See README.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
