"""The external baselines Section IV compares against, on the same corpus split.

Three systems, chosen because each fails differently and each is the strongest available
representative of a family the paper argues against:

* **Semgrep** - a rule-based static analyzer, the industry default for pull-request scanning.
* **Bandit** - a Python-specific security linter, so the comparison is not decided by a tool
  being at a disadvantage on the language the corpus is written in.
* **Single LLM** - one model, one prompt, one pass, no witnesses and no fusion. This is the
  ablation that isolates the contribution of multi-witness inference rather than of having a
  language model at all, so it uses the *same* model as the semantic witness.

**Every baseline is scored on exactly the corpus claims CodeSheriff is scored on.** A case is
a detection when the tool reports the pair's CWE on it, and the label comes from the corpus.
Comparing a tool's own benchmark numbers against ours would compare two datasets.

**A binary tool is scored at confidence 1.0.** Semgrep and Bandit emit a finding or nothing;
they publish no probability. Reporting ECE and Brier for them therefore means treating each
verdict as a claim of certainty, which is what it is - the absence of a confidence measure is
not neutrality, it is maximal overconfidence, and that is the comparison the paper is making.
This is stated in the caption rather than hidden in a footnote.

**The test split is refused by name**, for the reason `paper_eval.py` refuses it.

Semgrep and Bandit have no Windows build in this workspace; run this inside the corpus-run
image, where both are pinned (D-098):

    docker compose --profile corpus run --rm corpus-run
    python tools/baseline_eval.py --split validation --baselines semgrep bandit

The single-LLM baseline calls a hosted model and is therefore opt-in, never part of a test
run, and refuses to start without a key:

    python tools/baseline_eval.py --split validation --baselines single_llm
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codesheriff_corpus.loader import load_cases
from codesheriff_corpus.models import CorpusCase, Split
from codesheriff_corpus.splits import split_for
from codesheriff_engine.calibration.metrics import evaluate
from codesheriff_engine.calibration.prior import Prior, importance_weights

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS = REPO_ROOT / "docs" / "paper" / "results"

SEMGREP_CONFIGS = ["p/security-audit", "p/owasp-top-ten"]

# Bandit test ids -> CWE. Bandit publishes a CWE per test in recent versions; this table is
# the subset inside IN_SCOPE_CWES, so a Bandit finding outside our scope cannot be counted as
# a detection of something the corpus never asked about.
BANDIT_CWE = {
    "B102": "CWE-94",  # exec_used
    "B301": "CWE-502",  # pickle
    "B307": "CWE-94",  # eval
    "B308": "CWE-79",  # mark_safe
    "B310": "CWE-918",  # urllib_urlopen
    "B321": "CWE-918",  # ftplib
    "B323": "CWE-918",  # unverified_context
    "B506": "CWE-502",  # yaml_load
    "B601": "CWE-78",  # paramiko_calls
    "B602": "CWE-78",  # subprocess_popen_with_shell_equals_true
    "B605": "CWE-78",  # start_process_with_a_shell
    "B608": "CWE-89",  # hardcoded_sql_expressions
    "B105": "CWE-798",  # hardcoded_password_string
    "B106": "CWE-798",  # hardcoded_password_funcarg
    "B107": "CWE-798",  # hardcoded_password_default
}

CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _cases(split: str) -> list[CorpusCase]:
    if split == "test":
        raise SystemExit(
            "the test split is evaluated exactly once, at the end (PROJECT_CONTEXT.md 6)."
        )
    wanted = Split(split)
    return [c for c in load_cases() if split_for(c) is wanted]


def _write_case(case: CorpusCase, directory: Path) -> Path:
    """One file per case, named as the case names it, so a tool's path filters behave."""
    path = directory / f"{case.case_id}.py"
    path.write_text(case.post_src, encoding="utf-8")
    return path


def _run_semgrep(cases: Sequence[CorpusCase], binary: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {c.case_id: set() for c in cases}
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for case in cases:
            _write_case(case, directory)
        cmd = [binary, "--sarif", "--quiet", "--metrics=off"]
        for config in SEMGREP_CONFIGS:
            cmd.extend(["--config", config])
        cmd.append(str(directory))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
        if not proc.stdout.strip():
            raise SystemExit(f"semgrep produced no SARIF: {proc.stderr[:400]}")
        sarif = json.loads(proc.stdout)
    for run in sarif.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            case_id = Path(uri).stem
            if case_id not in found:
                continue
            rule = rules.get(result.get("ruleId"), {})
            blob = json.dumps(rule) + json.dumps(result.get("message", {}))
            for cwe in CWE_RE.findall(blob):
                found[case_id].add(cwe.upper())
    return found


def _run_bandit(cases: Sequence[CorpusCase], binary: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {c.case_id: set() for c in cases}
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for case in cases:
            _write_case(case, directory)
        proc = subprocess.run(
            [binary, "-r", str(directory), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if not proc.stdout.strip():
            raise SystemExit(f"bandit produced no JSON: {proc.stderr[:400]}")
        report = json.loads(proc.stdout)
    for issue in report.get("results", []):
        case_id = Path(issue["filename"]).stem
        if case_id not in found:
            continue
        cwe = issue.get("issue_cwe", {}).get("id")
        if cwe:
            found[case_id].add(f"CWE-{cwe}")
        elif issue.get("test_id") in BANDIT_CWE:
            found[case_id].add(BANDIT_CWE[issue["test_id"]])
    return found


def _run_single_llm(cases: Sequence[CorpusCase], model: str) -> dict[str, set[str]]:
    """One model, one prompt, one pass. No sentinel, no gate, no samples, no fusion.

    Deliberately naive: the point of this baseline is what a developer gets from asking a
    model directly, which is what the semantic witness is an elaboration of. Making it clever
    would measure the elaboration twice.
    """
    if not os.environ.get("GEMINI_API_KEY"):
        raise SystemExit("GEMINI_API_KEY is not set; the single-LLM baseline needs a key.")
    from pydantic import BaseModel  # local imports: this path is opt-in and costs money

    from semantic_agent.llm.hosted import HostedLLMClient

    class _Verdict(BaseModel):
        cwes: list[str]

    system_prompt = (
        "You are a security reviewer. Decide whether the Python function you are given "
        "contains a security vulnerability. Reply with every CWE identifier you are confident "
        "is present, or an empty list if the function is safe."
    )
    client = HostedLLMClient(api_key=os.environ["GEMINI_API_KEY"], model=model)
    found: dict[str, set[str]] = {}
    for case in cases:
        try:
            # n=1 and the agent's own temperature: one pass is the whole point of the
            # baseline, so the only difference from the semantic witness is the machinery.
            reply = client.generate(system_prompt, case.post_src, _Verdict, temperature=0.3)
        except Exception as exc:
            print(f"  {case.case_id}: call failed ({type(exc).__name__}); recorded as silence")
            found[case.case_id] = set()
            continue
        found[case.case_id] = {c.upper() for c in CWE_RE.findall(reply)}
    return found


def _score(
    name: str,
    cases: Sequence[CorpusCase],
    detections: dict[str, set[str]],
    prior: Prior,
    threshold: float,
) -> dict[str, Any]:
    labels = [c.is_vulnerable for c in cases]
    prevalence = sum(labels) / len(labels)
    positive, negative = importance_weights(prior, prevalence)
    weights = [positive if y else negative for y in labels]
    # A binary tool has no probability: a reported CWE is a claim of certainty.
    scores = [1.0 if c.cwe in detections.get(c.case_id, set()) else 0.0 for c in cases]

    tp = fp = fn = 0.0
    alerts = 0
    for s, y, w in zip(scores, labels, weights, strict=True):
        fired = s >= threshold
        alerts += int(fired)
        if fired and y:
            tp += w
        elif fired and not y:
            fp += w
        elif not fired and y:
            fn += w
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    m = evaluate(name, scores, labels, weights)
    return {
        "system": name,
        "ece": m.ece,
        "brier": m.brier,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "n_alerts": alerts,
        "n_cases": len(cases),
        "emits_probability": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", default="validation", choices=["calibration", "validation"])
    parser.add_argument(
        "--baselines",
        nargs="+",
        default=["semgrep", "bandit"],
        choices=["semgrep", "bandit", "single_llm"],
    )
    parser.add_argument("--semgrep-binary", default="semgrep")
    parser.add_argument("--bandit-binary", default="bandit")
    parser.add_argument(
        "--model", default=os.environ.get("SEMANTIC_MODEL", "gemini-3.1-flash-lite")
    )
    parser.add_argument("--out", default=str(RESULTS))
    args = parser.parse_args()

    from codesheriff_engine.calibration.artifact import active_artifact

    artifact = active_artifact()
    prior = artifact.prior
    threshold = artifact.threshold.value

    cases = _cases(args.split)
    print(f"split={args.split}  cases={len(cases)}  threshold={threshold:.4f}")

    rows = []
    for baseline in args.baselines:
        print(f"running {baseline} ...")
        if baseline == "semgrep":
            detections = _run_semgrep(cases, args.semgrep_binary)
        elif baseline == "bandit":
            detections = _run_bandit(cases, args.bandit_binary)
        else:
            detections = _run_single_llm(cases, args.model)
        rows.append(_score(baseline, cases, detections, prior, threshold))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"baselines_{args.split}.json"
    path.write_text(
        json.dumps({"split": args.split, "threshold": threshold, "systems": rows}, indent=2),
        encoding="utf-8",
    )

    print(f"\n{'system':12} {'ECE':>7} {'Brier':>7} {'Prec':>6} {'Rec':>6} {'F1':>6} {'alerts':>6}")
    for row in rows:
        print(
            f"{row['system']:12} {row['ece']:7.4f} {row['brier']:7.4f} {row['precision']:6.3f} "
            f"{row['recall']:6.3f} {row['f1']:6.3f} {row['n_alerts']:6}"
        )
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
