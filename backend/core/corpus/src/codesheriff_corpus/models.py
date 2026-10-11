"""The corpus schema.

A case is one labelled `ChangeUnit`. Cases come in twin pairs: the same function,
same file, same symbol, same CWE — once with the vulnerability and once without.
The pair is what makes a false positive measurable. An agent that flags the
vulnerable member has found something; an agent that flags both has found nothing
and is reacting to the shape of the code.

Twins share a `finding_key` by construction (same file, same qualified symbol, same
CWE), so "did this agent fire on the safe twin" is a lookup, not a judgement.
"""

from __future__ import annotations

import difflib
import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_serializer, field_validator, model_validator

from codesheriff_contracts import IN_SCOPE_CWES, ChangeUnit

CORPUS_REPO = "codesheriff/corpus"
"""Synthetic repository name. Cases are hand-written (PROJECT_CONTEXT.md §5), so there
is no real repo — but `ChangeUnit.repo` is not optional and the context agent's
retrieval is repository-scoped, so the value has to be stable."""


class Label(StrEnum):
    """Ground truth for one case. Certain, or the case does not belong here."""

    VULNERABLE = "vulnerable"
    SAFE = "safe"


class Split(StrEnum):
    """Which question this case is allowed to answer (PROJECT_CONTEXT.md §6)."""

    CALIBRATION = "calibration"
    """Likelihood ratios and the prior are fitted here. Nothing else."""

    VALIDATION = "validation"
    """The alert threshold is swept here. Ratios are already frozen."""

    TEST = "test"
    """Evaluated exactly once, at the very end. Never looked at before."""


KNOWN_AGENT_IDS: frozenset[str] = frozenset(
    {
        "structural.taint",
        "structural.semgrep",
        "semantic.hosted",
        "context.rag",
        "runtime.sfi",
    }
)
"""The agent ids `detectable_by` may name. A typo here would silently excuse a miss
forever, because nothing downstream would ever match the name."""


class PrecedentRecord(BaseModel):
    """One excerpt of merged code this case's repository already accepted.

    A cross-PR scenario is a case *plus a history* — the shape Chapter 7 deferred to
    Chapter 12 rather than guess at. This is that shape, and it is deliberately the
    same shape `codesheriff_storage.PrecedentChunk` holds in production: one merged
    pull request, one file, one qualified symbol, one bounded excerpt of source. A
    corpus history that described precedent differently from the way the database
    stores it would measure an agent that does not exist.

    Indexing is **per symbol, not per pull request** (PROJECT_CONTEXT.md §5).
    `BAAI/bge-small-en-v1.5` truncates at 512 tokens, so a PR-level document is
    silently cut and matches poorly against a function-level query.
    """

    model_config = ConfigDict(frozen=True)

    pr_number: int
    """Which merged pull request accepted this. Ordering is by this and the symbol,
    so a history reads as a timeline rather than as a set."""

    file: str
    qualified_symbol: str
    """`Class.method` or a bare function name, matching `ChangeUnit.qualified_symbol`.

    Not optional here, unlike the production column. Precedent whose symbol is unknown
    could never establish a convention *about* a symbol, so a corpus history has no use
    for one, and permitting it would invite a case that cannot fail.
    """

    accepted_src: str
    """The merged source of that symbol, read from `precedent/` beside the case."""

    @field_validator("accepted_src")
    @classmethod
    def _source_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a precedent record with no source establishes nothing")
        return value


class CorpusCase(BaseModel):
    """One labelled unit of analysis.

    `detectable_by` is the field to be suspicious of. It exists so a static miss on a
    semantic-only case is not scored as a failure (PROJECT_CONTEXT.md §5), and it is
    exactly the field that could excuse any miss if it were edited after seeing
    results. It is authored with the case, before any agent runs, from the rule
    recorded in DECISIONS.md D-047 — not adjusted afterwards.
    """

    model_config = ConfigDict(frozen=True)

    case_id: str
    pair_id: str
    label: Label
    cwe: str
    """The CWE this pair is about. Present on BOTH members: the safe twin is not
    "about nothing", it is the case where this specific CWE must NOT be reported."""

    detectable_by: frozenset[str] = frozenset()
    """Agents that could in principle find this, on the vulnerable member only.

    Empty on safe twins — there is nothing there to detect, and every agent is
    equally required to stay quiet.
    """

    rationale: str
    """Why this label is certain. Every label in a hand-written corpus has to be
    defensible in the paper; a case whose rationale is hard to write is a case whose
    label is not certain enough to keep."""

    language: str = "python"
    file: str
    symbol: str
    enclosing_class: str | None = None
    decorators: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    start_line: int = 1
    is_test_file: bool = False

    post_src: str
    pre_src: str | None = None

    precedent: tuple[PrecedentRecord, ...] = ()
    """Merged code this repository accepted before this change (Chapter 12).

    Empty on most cases, and that emptiness is a real condition rather than a gap:
    `context.rag`'s documented failure mode is a repository with no relevant history,
    and a case with no precedent is how that abstention gets measured.

    Both twins of a pair carry the **same** history. The safe twin exists so that a
    rule keyed on the shape of the code rather than on the flaw fires on both members
    and is caught doing it; a twin whose history differed would let the agent be right
    on the pair for the wrong reason. `test_twins_share_a_precedent_history` asserts it.
    """

    # -- serialisation ------------------------------------------------------

    @field_serializer("detectable_by")
    def _serialise_detectable_by(self, value: frozenset[str]) -> list[str]:
        """Sorted on the wire, because `corpus_hash` is computed over this.

        A frozenset iterates in an order derived from the hashes of its members, and
        Python randomises string hashing per process. Without this, the serialised case
        differs between two runs of the same code on the same file, and `corpus_hash`
        differs with it — so a calibration run could never be shown to match the corpus
        it was fitted on, which is the one thing the hash exists to do.

        Exactly the reason `Evidence.covered_cwes` carries the same serialiser (D-024).
        Found here by the hash changing between two invocations of the CLI.
        """
        return sorted(value)

    # -- validation ---------------------------------------------------------

    @field_validator("cwe")
    @classmethod
    def _cwe_in_scope(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in IN_SCOPE_CWES:
            raise ValueError(
                f"{value!r} is outside IN_SCOPE_CWES. The set is closed; widening it "
                "invalidates every number already fitted against it."
            )
        return normalized

    @field_validator("rationale")
    @classmethod
    def _rationale_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("every case states why its label is certain")
        return value.strip()

    @model_validator(mode="after")
    def _check_case(self) -> CorpusCase:
        suffix = "vuln" if self.label is Label.VULNERABLE else "safe"
        expected = f"{self.pair_id}-{suffix}"
        if self.case_id != expected:
            raise ValueError(
                f"case_id {self.case_id!r} must be {expected!r}. Pairing is derived from "
                "the id rather than declared, so a twin cannot drift from its pair."
            )

        if self.label is Label.VULNERABLE:
            if not self.detectable_by:
                raise ValueError(
                    "a vulnerable case no agent could detect is unscoreable: every agent "
                    "would be excused, so the case contributes nothing to any ratio"
                )
            unknown = self.detectable_by - KNOWN_AGENT_IDS
            if unknown:
                raise ValueError(f"detectable_by names unknown agents: {sorted(unknown)}")
        elif self.detectable_by:
            raise ValueError(
                "detectable_by belongs to vulnerable cases. A safe twin holds nothing to "
                "detect, and every agent is equally required to stay silent on it."
            )

        if not self.post_src.strip():
            raise ValueError("post_src is the unit under analysis and cannot be empty")
        return self

    # -- derived ------------------------------------------------------------

    @property
    def base_sha(self) -> str:
        """Derived from content, not invented. Two runs of the loader agree."""
        return hashlib.sha256((self.pre_src or "").encode("utf-8")).hexdigest()[:40]

    @property
    def head_sha(self) -> str:
        return hashlib.sha256(self.post_src.encode("utf-8")).hexdigest()[:40]

    @property
    def changed_lines(self) -> list[int]:
        """Absolute line numbers in `post_src` that this change touched.

        A pure deletion — the CWE-862 case where a PR removes `@login_required` — adds
        no line to post, so it would otherwise report that nothing changed. The line
        the deletion sits against is included instead, because that removal is the
        entire signal for the access-control CWEs (D-013).
        """
        post_lines = self.post_src.splitlines()
        if self.pre_src is None:
            return [self.start_line + i for i in range(len(post_lines))]

        matcher = difflib.SequenceMatcher(a=self.pre_src.splitlines(), b=post_lines, autojunk=False)
        changed: list[int] = []
        for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
            if tag in {"replace", "insert"}:
                changed.extend(self.start_line + j for j in range(j1, j2))
            elif tag == "delete" and post_lines:
                changed.append(self.start_line + min(j1, len(post_lines) - 1))
        return sorted(set(changed))

    @property
    def unit(self) -> ChangeUnit:
        """The `ChangeUnit` an agent receives. Identical in shape to a production one.

        No `PRContext` is attached, and none exists to attach: PR prose is held
        separately precisely so that a corpus run and a production run are the same
        run (D-014).
        """
        return ChangeUnit(
            unit_id=self.case_id,
            repo=CORPUS_REPO,
            language=self.language,
            file=self.file,
            symbol=self.symbol,
            enclosing_class=self.enclosing_class,
            decorators=list(self.decorators),
            pre_src=self.pre_src,
            post_src=self.post_src,
            changed_lines=self.changed_lines,
            start_line=self.start_line,
            imports=list(self.imports),
            base_sha=self.base_sha,
            head_sha=self.head_sha,
            is_test_file=self.is_test_file,
        )

    @property
    def expected_key(self) -> str:
        """The `finding_key` this pair is about.

        On a vulnerable case: the key an agent must produce to have found it. On its
        safe twin: the key an agent must NOT produce. The same value for both — that
        identity is the entire point of a twin pair.

        Built through `ChangeUnit.key_for`, never assembled here (D-019).
        """
        return self.unit.key_for(self.cwe)

    @property
    def is_vulnerable(self) -> bool:
        return self.label is Label.VULNERABLE

    def detectable(self, agent_id: str) -> bool:
        """Whether a miss by `agent_id` on this case counts against it."""
        return agent_id in self.detectable_by
