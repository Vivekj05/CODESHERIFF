"""Section IV's numbers: fusion, ablations and comparators, from recorded observations.

Everything here is computed **through the production arithmetic**. Posteriors come from
`fusion.bayes.posterior_from_cells`, the same function `compute_bayesian_fusion` calls to
produce the number a developer is shown, and the metrics come from
`calibration.metrics.evaluate`. A paper that re-implemented the odds product would be
reporting a quantity the engine does not emit.

**The test split is not reachable from here.** Section 6 permits it to be evaluated exactly
once, and this script runs on every re-read of the paper. `_load` refuses it by name, for the
reason `codesheriff_worker.calibration.runner` does: a harness that would run on the test
split if asked is a harness that eventually will be.

Nothing here calls a model, opens a socket or touches a database. It reads two committed
JSONL files and one committed artifact, so a re-run reproduces the table exactly.

    python tools/paper_eval.py --split validation
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codesheriff_engine.calibration.artifact import active_artifact
from codesheriff_engine.calibration.metrics import evaluate
from codesheriff_engine.calibration.observations import Claim
from codesheriff_engine.calibration.prior import Prior
from codesheriff_engine.calibration.scoring import weights_for
from codesheriff_engine.fusion.bayes import posterior_from_cells
from codesheriff_engine.fusion.cells import RatioCell
from codesheriff_engine.fusion.witnesses import WITNESSES

REPO_ROOT = Path(__file__).resolve().parents[1]
OBSERVATIONS = REPO_ROOT / "calibration" / "observations"
RESULTS = REPO_ROOT / "docs" / "paper" / "results"

DETECTION_CELLS = {
    RatioCell.DETECTION_LOW,
    RatioCell.DETECTION_MEDIUM,
    RatioCell.DETECTION_HIGH,
}


def _load(split: str) -> list[Claim]:
    if split == "test":
        raise SystemExit(
            "the test split is evaluated exactly once, at the end (PROJECT_CONTEXT.md 6). "
            "It is not available to a script that regenerates a table."
        )
    path = OBSERVATIONS / f"{split}.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    return [Claim.model_validate_json(line) for line in lines[1:]]


def _confusion(
    posteriors: Sequence[float],
    labels: Sequence[bool],
    weights: Sequence[float],
    threshold: float,
) -> dict[str, float]:
    """Weighted confusion at one cut point, plus the unweighted alert count.

    Weighted, because a rate counted raw on a twin-paired split describes a population in
    which half of all changed functions are vulnerable, and no threshold chosen there is the
    threshold production needs.
    """
    tp = fp = fn = tn = 0.0
    alerts = 0
    for p, y, w in zip(posteriors, labels, weights, strict=True):
        fired = p >= threshold
        alerts += int(fired)
        if fired and y:
            tp += w
        elif fired and not y:
            fp += w
        elif not fired and y:
            fn += w
        else:
            tn += w
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "n_alerts": alerts,
    }


def _majority_vote(claim: Claim) -> float:
    """The comparator the plan names: a verdict by counting witnesses, not weighing them.

    Each witness that emitted a detection votes yes; a silence votes no; an abstention does
    not vote, because a witness that could not run has not disagreed with anything. The score
    is the yes-fraction among the witnesses that voted, which is what a voting system can
    offer in place of a probability. It is deliberately NOT a posterior: it has no prior, so
    it cannot be moved by the base rate, and that is the whole point of the comparison.
    """
    yes = no = 0
    for witness in WITNESSES:
        cell = claim.cells.get(witness)
        if cell is None:
            continue
        if cell in DETECTION_CELLS:
            yes += 1
        elif cell is RatioCell.SILENCE:
            no += 1
    voted = yes + no
    return yes / voted if voted else 0.0


def _without(claim: Claim, dropped: str) -> Mapping[str, RatioCell | None]:
    """The claim as it would have been had `dropped` never run - an abstention, at 1.0."""
    return {w: (None if w == dropped else c) for w, c in claim.cells.items()}


def _row(
    name: str,
    posteriors: Sequence[float],
    claims: Sequence[Claim],
    weights: Sequence[float],
    threshold: float,
    split: str,
) -> dict[str, Any]:
    labels = [c.label for c in claims]
    m = evaluate(split, posteriors, labels, weights)
    row: dict[str, Any] = {
        "system": name,
        "ece": m.ece,
        "brier": m.brier,
        "mean_posterior": m.mean_posterior,
        "observed_rate": m.observed_rate,
        "n_claims": m.n_claims,
    }
    row.update(_confusion(posteriors, labels, weights, threshold))
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", default="validation", choices=["calibration", "validation"])
    parser.add_argument("--out", default=str(RESULTS))
    args = parser.parse_args()

    artifact = active_artifact()
    table = artifact.table()
    prior: Prior = artifact.prior
    threshold = artifact.threshold.value

    claims = _load(args.split)
    weights = weights_for(claims, prior)

    full = [posterior_from_cells(c.cells, table, prior.base_rate) for c in claims]
    rows = [_row("CodeSheriff (full)", full, claims, weights, threshold, args.split)]

    # Comparator: majority voting over the same statements, scored at the same cut point.
    vote = [_majority_vote(c) for c in claims]
    rows.append(_row("Majority vote", vote, claims, weights, threshold, args.split))

    # Comparator: the prior alone - what the system scores having heard from nobody. It is
    # the floor any witness has to beat, and its ECE is not bad, which is the point.
    prior_only = [prior.base_rate] * len(claims)
    rows.append(_row("Prior only (no witness)", prior_only, claims, weights, threshold, args.split))

    # Ablations: one witness at a time, replaced by the abstention it would have produced.
    ablations = []
    for dropped in WITNESSES:
        posteriors = [
            posterior_from_cells(_without(c, dropped), table, prior.base_rate) for c in claims
        ]
        ablations.append(
            _row(f"without {dropped}", posteriors, claims, weights, threshold, args.split)
        )

    # Per-witness stance counts, by label. The denominator of every ratio in the artifact.
    stances: dict[str, dict[str, dict[str, int]]] = {}
    for witness in WITNESSES:
        by_label: dict[str, dict[str, int]] = {"vulnerable": {}, "safe": {}}
        for claim in claims:
            cell = claim.cells.get(witness)
            name = cell.value if cell is not None else "abstention"
            bucket = by_label["vulnerable" if claim.label else "safe"]
            bucket[name] = bucket.get(name, 0) + 1
        stances[witness] = by_label

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "split": args.split,
        "corpus_hash": artifact.corpus_hash,
        "split_hash": artifact.split_hash,
        "threshold": threshold,
        "base_rate": prior.base_rate,
        "n_claims": len(claims),
        "n_vulnerable": sum(c.label for c in claims),
        "systems": rows,
        "ablations": ablations,
        "stances": stances,
    }
    (out / f"eval_{args.split}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    fields = ["system", "ece", "brier", "precision", "recall", "f1", "n_alerts"]
    csv_lines = [",".join(fields)]
    for row in rows + ablations:
        csv_lines.append(
            ",".join(f"{row[f]:.4f}" if isinstance(row[f], float) else str(row[f]) for f in fields)
        )
    (out / f"eval_{args.split}.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")

    width = max(len(r["system"]) for r in rows + ablations)
    print(
        f"split={args.split}  n={len(claims)}  "
        f"threshold={threshold:.4f}  base_rate={prior.base_rate}"
    )
    head = f"{'system':{width}}  {'ECE':>7} {'Brier':>7} {'Prec':>6} {'Rec':>6}"
    print(f"{head} {'F1':>6} {'alerts':>6}")
    for row in rows + ablations:
        print(
            f"{row['system']:{width}}  {row['ece']:7.4f} {row['brier']:7.4f} "
            f"{row['precision']:6.3f} {row['recall']:6.3f} {row['f1']:6.3f} {row['n_alerts']:6}"
        )
    print(f"\nwrote {out / f'eval_{args.split}.json'}")


if __name__ == "__main__":
    main()
