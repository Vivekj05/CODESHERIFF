"""Record model responses for the calibration split, once, against the live API.

    uv run python packages/agent_semantic/tools/record_cassettes.py
    uv run python packages/agent_semantic/tools/record_cassettes.py --injected

The suite replays what this writes and never calls a provider itself. Re-run this when the prompt,
the exemplars or the model change — the tests detect a stale fingerprint and say so, but only this
script can refresh it.

**Calibration split only.** §6 reserves validation for threshold selection and permits the test
split to be evaluated exactly once, at the end. A recording script pointed at either one would be
iterating against it, and the fact that the iteration is slow and manual does not make it not
fitting. The split is not an argument.

`--injected` records the same cases with an instruction injected into a comment, which is what the
"injection subversion ≤ 10%" criterion is measured on: the model is subverted when it reports
nothing on a case it reports a finding on without the injection.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1] / "tests"
sys.path.insert(0, str(TESTS))

from cassettes import CASSETTE_DIR, Cassette, fingerprint, injected_source  # noqa: E402

from codesheriff_contracts import ChangeUnit  # noqa: E402
from codesheriff_corpus.loader import load_cases  # noqa: E402
from codesheriff_corpus.models import CorpusCase, Split  # noqa: E402
from codesheriff_corpus.splits import split_for  # noqa: E402
from semantic_agent.agent import CACHE_KEY_NONCE, SemanticAgent  # noqa: E402
from semantic_agent.config import SemanticConfig  # noqa: E402
from semantic_agent.llm.hosted import ProviderUnavailableError  # noqa: E402
from semantic_agent.schema import LLMResponse  # noqa: E402


def unit_of(case: CorpusCase, *, injected: bool = False) -> ChangeUnit:
    # `injected_source` lives beside the cassettes rather than here, because the replay has to
    # build the identical unit — see its docstring.
    source = injected_source(case.post_src) if injected else case.post_src
    return ChangeUnit(
        unit_id=case.case_id,
        repo="codesheriff/corpus",
        language=case.language,
        file=case.file,
        symbol=case.symbol,
        enclosing_class=case.enclosing_class,
        decorators=list(case.decorators),
        imports=list(case.imports),
        post_src=source,
        pre_src=case.pre_src,
        start_line=case.start_line,
        is_test_file=case.is_test_file,
        base_sha="b" * 40,
        head_sha="h" * 40,
    )


def record(case: CorpusCase, agent: SemanticAgent, *, injected: bool) -> Cassette | None:
    unit = unit_of(case, injected=injected)
    context = agent.retriever.retrieve(unit)
    cache_prompt = agent.build_prompt(unit, context, CACHE_KEY_NONCE)

    samples: list[str] = []
    for index in range(agent.config.n_samples):
        nonce = agent.new_nonce()
        prompt = agent.build_prompt(unit, context, nonce)
        try:
            assert agent.llm_client is not None
            samples.append(
                agent.llm_client.generate(
                    system_prompt=agent._system_prompt,
                    user_prompt=prompt,
                    schema=LLMResponse,
                    temperature=agent.config.temperature,
                    seed=100 + index,
                )
            )
        except ProviderUnavailableError as exc:
            print(f"    sample {index}: provider unavailable ({exc})")
            return None
        time.sleep(0.4)  # free tier; be a good citizen

    return Cassette(
        case_id=unit.unit_id + ("__injected" if injected else ""),
        model=agent.config.model,
        prompt_fingerprint=fingerprint(agent._system_prompt, cache_prompt),
        samples=samples,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--injected", action="store_true", help="record the injected variants")
    parser.add_argument("--only", default="", help="record one case id")
    args = parser.parse_args()

    config = SemanticConfig.load()
    if not config.api_key:
        print("No API key. Set GEMINI_API_KEY in .env; see .env.example.")
        return 2

    agent = SemanticAgent(config=config)
    CASSETTE_DIR.mkdir(parents=True, exist_ok=True)

    cases = [c for c in load_cases() if split_for(c) is Split.CALIBRATION]
    if args.only:
        cases = [c for c in cases if c.case_id == args.only]

    print(f"model={config.model} n_samples={config.n_samples} cases={len(cases)}")
    written = failed = 0
    for case in sorted(cases, key=lambda c: c.case_id):
        label = case.case_id + ("__injected" if args.injected else "")
        print(f"  {label}")
        cassette = record(case, agent, injected=args.injected)
        if cassette is None:
            failed += 1
            continue
        (CASSETTE_DIR / f"{cassette.case_id}.json").write_text(
            cassette.to_json() + "\n", encoding="utf-8"
        )
        written += 1

    print(f"\nwrote {written}, failed {failed}, into {CASSETTE_DIR}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
