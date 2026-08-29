"""The names in `.env.example` are the names the code reads.

This file exists because they were not. `SemanticConfig` carried `env_prefix="LLM_"` while
`.env.example` documented `SEMANTIC_*`, and `load()` reached for the key with
`os.getenv("GEMINI_API_KEY")` — which reads the *process* environment, while `pydantic-settings`
parses `.env` into the settings object without exporting anything to `os.environ`.

So following `.env.example` exactly produced `api_key=None`, and the agent abstained on every unit.
The abstention was honest, which is precisely what made it hard to see: the system correctly
reported that it could not run, and the reason was that the documented way to configure it did
nothing.

`test_every_documented_key_is_read` is the durable form — it parses `.env.example` and fails if a
name drifts on either side.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from semantic_agent.config import AGENT_ID, SemanticConfig

ENV_EXAMPLE = Path(__file__).resolve().parents[3] / ".env.example"

DOCUMENTED = {
    "GEMINI_API_KEY": "api_key",
    "SEMANTIC_MODEL": "model",
    "SEMANTIC_N_SAMPLES": "n_samples",
    "SEMANTIC_TEMPERATURE": "temperature",
    "SEMANTIC_CACHE_PATH": "cache_path",
    "SEMANTIC_BUDGET_PER_UNIT": "budget_usd_per_unit",
}


def aliases_of(field_name: str) -> set[str]:
    """Every environment name that fills `field_name`."""
    info = SemanticConfig.model_fields[field_name]
    alias = info.validation_alias or info.alias
    if alias is None:
        return {field_name.upper()}
    if isinstance(alias, str):
        return {alias}
    return {choice for choice in alias.choices if isinstance(choice, str)}


@pytest.mark.parametrize(("env_name", "field_name"), sorted(DOCUMENTED.items()))
def test_every_documented_key_is_read(env_name: str, field_name: str) -> None:
    """A configuration key the code does not read is not configuration; it is a claim."""
    assert env_name in aliases_of(field_name)


def test_env_example_documents_nothing_the_code_ignores() -> None:
    """The other direction: a `SEMANTIC_*` line nobody reads is a trap for whoever sets it."""
    if not ENV_EXAMPLE.exists():  # pragma: no cover - the file is committed
        pytest.skip(".env.example is not present")

    declared = set(
        re.findall(r"^([A-Z][A-Z0-9_]*)=", ENV_EXAMPLE.read_text(encoding="utf-8"), re.M)
    )
    semantic_keys = {key for key in declared if key.startswith("SEMANTIC_")}
    read = set().union(*(aliases_of(name) for name in SemanticConfig.model_fields))

    assert semantic_keys <= read, f"documented but read by nothing: {sorted(semantic_keys - read)}"


def test_a_dotenv_key_reaches_the_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact failure: `GEMINI_API_KEY` in a `.env` file, as `.env.example` instructs."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    (tmp_path / ".env").write_text("GEMINI_API_KEY=key-from-dotenv\n", encoding="utf-8")

    assert SemanticConfig.load().api_key == "key-from-dotenv"


def test_the_process_environment_overrides_dotenv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """So a one-off `GEMINI_API_KEY=... uv run ...` does what it looks like it does."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("GEMINI_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("GEMINI_API_KEY", "from-environment")

    assert SemanticConfig.load().api_key == "from-environment"


@pytest.mark.parametrize("name", ["GOOGLE_API_KEY", "LLM_API_KEY"])
def test_the_alternative_key_names_still_work(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Google's own tooling exports `GOOGLE_API_KEY`; accepting it saves a confusing hour."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv(name, "alternative")

    assert SemanticConfig.load().api_key == "alternative"


def test_no_key_anywhere_leaves_it_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset is what makes the agent abstain rather than substitute a stub (D-057)."""
    monkeypatch.chdir(tmp_path)
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)

    assert SemanticConfig.load().api_key is None


def test_the_agent_id_is_not_configurable() -> None:
    """Fusion refuses an `agent_id` that maps to no witness (D-052).

    An environment variable that could rename this witness is a way to make every audit raise, and
    the identity is what the fitted likelihood ratios will be attached to.
    """
    assert "agent_id" not in SemanticConfig.model_fields
    assert SemanticConfig().agent_id == AGENT_ID == "semantic.hosted"


def default_model() -> str:
    """The field default, read without instantiating.

    `SemanticConfig()` would load the developer's own `.env`, so this assertion would pass or fail
    depending on which model that machine happens to be pointed at — which is exactly the kind of
    environment-dependent test that teaches people to ignore a red suite.
    """
    return str(SemanticConfig.model_fields["model"].default)


def test_the_default_model_agrees_with_env_example() -> None:
    """The two must not drift, or the documented setup silently changes behaviour.

    Read from the file rather than hard-coded here, so bumping the model is one edit and this test
    keeps checking the thing that matters instead of becoming a second place to update.
    """
    if not ENV_EXAMPLE.exists():  # pragma: no cover - the file is committed
        pytest.skip(".env.example is not present")

    documented = re.search(r"^SEMANTIC_MODEL=(.+)$", ENV_EXAMPLE.read_text(encoding="utf-8"), re.M)
    assert documented is not None
    assert default_model() == documented.group(1).strip()


def test_the_default_model_is_pinned_not_floating() -> None:
    """A `-latest` alias can change the model between the run that fits the likelihood ratios and
    every run scored against them, which makes a calibration figure unreproducible (§6)."""
    assert not default_model().endswith("-latest")
