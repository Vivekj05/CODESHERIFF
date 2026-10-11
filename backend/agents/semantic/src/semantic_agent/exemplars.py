"""Loading the few-shot exemplars, and rendering them into the prompt.

`AUDIT.md` 3.9: three exemplar files sat in `prompts/exemplars/` and a repo-wide grep for
`exemplar` returned three hits, all in Markdown. Zero Python referenced them. The mechanism §5
specifies to teach "safe-by-default is an acceptable answer" was inert, and only a prose
instruction survived.

They also could not have been loaded as they stood: each file held only a `response`, with no
record of the code it was a response *to*. Half of every example was missing, so wiring them up
meant authoring the input half — see the `unit` key in each file.

**Two of the three report nothing.** That ratio is the point. A model shown only findings learns
that finding something is what a good answer looks like, which is the sycophancy this agent is
measured against; the safe examples are what make `{"findings": []}` a demonstrated answer rather
than a permitted one. `exemplar_balance` asserts the ratio so it cannot drift.

**No exemplar is drawn from the corpus.** An example lifted from a labelled case would put that
case's answer in the prompt, which is label leakage into the thing being measured (D-047).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from semantic_agent.schema import LLMResponse

logger = logging.getLogger(__name__)

EXEMPLARS_DIR = Path(__file__).parent / "prompts" / "exemplars"


@dataclass(frozen=True)
class Exemplar:
    """One worked example: the code, and the correct answer for it."""

    name: str
    note: str
    file: str
    symbol: str
    language: str
    post_src: str
    response: LLMResponse

    @property
    def reports_a_finding(self) -> bool:
        return bool(self.response.findings)


def _load_one(path: Path) -> Exemplar | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        unit = raw["unit"]
        return Exemplar(
            name=path.stem,
            note=str(raw.get("note", "")),
            file=str(unit["file"]),
            symbol=str(unit.get("symbol", "<module>")),
            language=str(unit.get("language", "python")),
            post_src=str(unit["post_src"]),
            # Validated against the same schema the model must satisfy. An exemplar that would be
            # rejected by the hallucination gate is teaching the model to produce rejects.
            response=LLMResponse.model_validate(raw["response"]),
        )
    except Exception as exc:
        logger.error("Exemplar %s failed to load and will not be shown to the model: %s", path, exc)
        return None


@lru_cache(maxsize=1)
def load_exemplars(directory: Path | None = None) -> tuple[Exemplar, ...]:
    """Every valid exemplar, in filename order. Cached — the files do not change at runtime."""
    root = directory or EXEMPLARS_DIR
    if not root.is_dir():
        logger.error("No exemplars directory at %s; the model will get no worked examples", root)
        return ()

    loaded = [_load_one(path) for path in sorted(root.glob("*.json"))]
    kept = tuple(item for item in loaded if item is not None)
    if not kept:
        logger.error("No exemplars loaded from %s", root)
    return kept


def exemplar_balance(exemplars: tuple[Exemplar, ...]) -> tuple[int, int]:
    """`(reporting, silent)` counts. The second number is the anti-sycophancy one."""
    reporting = sum(1 for item in exemplars if item.reports_a_finding)
    return reporting, len(exemplars) - reporting


def render_exemplars(exemplars: tuple[Exemplar, ...], nonce: str) -> str:
    """The worked examples as prompt text, inside the same sentinel the real unit uses.

    Deliberately the same delimiter. An example presented in a *different* frame would teach the
    model that the sentinel is decorative; presenting them identically teaches that everything
    inside one is code to be judged, which is the behaviour the real request depends on.
    """
    if not exemplars:
        return ""

    blocks = ["Worked examples. Each shows a unit and the correct response for it.\n"]
    for item in exemplars:
        answer = item.response.model_dump(mode="json", exclude_none=True)
        blocks.append(
            f"Example — {item.name}\n"
            f"File: {item.file} · Symbol: {item.symbol}\n\n"
            f"BEGIN {nonce}\n"
            f"--- AFTER ---\n"
            f"{item.post_src.rstrip()}\n"
            f"END {nonce}\n\n"
            f"Correct response:\n"
            f"{json.dumps(answer, indent=2)}\n"
        )

    reporting, silent = exemplar_balance(exemplars)
    blocks.append(
        f"({reporting} of these {len(exemplars)} report a finding; {silent} correctly report "
        f"nothing. Reporting nothing is a complete answer.)\n"
    )
    return "\n".join(blocks)
