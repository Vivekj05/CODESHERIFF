"""The calibration endpoint: the evidence behind the number, not just the number.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029) — the route is behind a
session like every other, and a session needs a database.

What is asserted here is mostly *absence of computation*. The route's whole job is to hand over
`calibration.json` unaltered, so the tests compare its output against the artifact rather than
against literals: a re-fit must move both sides together, and a route that rounded, recomputed or
defaulted anything would move only one.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from codesheriff_engine.calibration import CalibrationError, active_artifact

pytestmark = pytest.mark.db


def sign_in(client: TestClient) -> None:
    response = client.get("/auth/login", params={"next": "/calibration"})
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    callback = client.get("/auth/callback", params={"code": "good-code", "state": state})
    assert callback.status_code == 303, callback.text


def test_it_serves_the_artifact_s_own_numbers(client: TestClient) -> None:
    """No rounding, no recomputation. `calibration.json` is the only source (D-080)."""
    sign_in(client)
    artifact = active_artifact()

    body: dict[str, Any] = client.get("/calibration").json()

    assert body["source"] == "packaged"
    assert body["artifact"]["corpus_hash"] == artifact.corpus_hash
    assert body["artifact"]["split_hash"] == artifact.split_hash
    assert body["artifact"]["threshold"]["value"] == pytest.approx(artifact.alert_threshold)
    assert body["artifact"]["prior"]["base_rate"] == pytest.approx(artifact.base_rate)


def test_the_prior_is_reported_as_declared_not_as_measured(client: TestClient) -> None:
    """D-083: a twin-paired corpus has a prevalence of 0.5 by construction.

    The dashboard has to be able to say which of the two the base rate is, so the endpoint carries
    `source` and the prevalence it was rescaled from rather than the rate alone.
    """
    sign_in(client)

    prior = client.get("/calibration").json()["artifact"]["prior"]

    assert prior["source"] == "declared"
    assert prior["corpus_prevalence"] == pytest.approx(0.5, abs=0.05)


def test_every_ratio_arrives_with_the_counts_behind_it(client: TestClient) -> None:
    """A ratio held up entirely by Laplace smoothing must look like one on screen.

    `structural.detection_high` is the standing example: it exceeds `detection_medium` because
    exactly one true detection landed in it, not because a confident taint path is weaker
    evidence. Without the counts that is invisible and reads as a fitted surprise.
    """
    sign_in(client)

    witnesses = client.get("/calibration").json()["artifact"]["fit"]["witnesses"]

    assert set(witnesses) == {"structural", "semantic", "context", "runtime"}
    for fit in witnesses.values():
        assert fit["cells"], "a witness arrived with no cells"
        for cell in fit["cells"].values():
            assert "n_vulnerable" in cell
            assert "n_safe" in cell
            assert "smoothed_ratio" in cell
            assert cell["ratio"] > 0.0


def test_the_reliability_bins_and_the_whole_sweep_travel(client: TestClient) -> None:
    """ECE without its bins is a number asking to be trusted, which is the failure being attacked.

    Same for the threshold: the selected value alone says nothing about how sharply it was
    selected, and the sweep is what shows whether the neighbouring thresholds were nearly as good.
    """
    sign_in(client)

    artifact = client.get("/calibration").json()["artifact"]

    validation = artifact["metrics"]["validation"]
    assert validation["bins"], "reliability bins did not travel"
    assert {"lower", "upper", "n", "mean_confidence", "observed_frequency"} <= set(
        validation["bins"][0]
    )
    assert len(artifact["threshold"]["sweep"]) > 1


def test_the_backends_are_grouped_under_their_witness(client: TestClient) -> None:
    """D-052 on screen: `structural.semgrep` is not a peer of `semantic.hosted`.

    Four witnesses, whatever the backend count. A UI handed a flat list of agents would draw the
    independence violation the fusion engine refuses to make.
    """
    sign_in(client)

    witnesses = client.get("/calibration").json()["witnesses"]

    assert [row["witness"] for row in witnesses] == [
        "structural",
        "semantic",
        "context",
        "runtime",
    ]
    structural = next(row for row in witnesses if row["witness"] == "structural")
    assert set(structural["agents"]) == {"structural.taint", "structural.semgrep"}


def test_the_provenance_says_which_backends_were_actually_running(client: TestClient) -> None:
    """A structural ratio fitted with no Semgrep build describes a one-backend witness.

    That is a property of the number, and the dashboard must be able to show it as one.
    """
    sign_in(client)

    provenance = client.get("/calibration").json()["artifact"]["provenance"]

    assert provenance, "the artifact carries no provenance"
    for run in provenance.values():
        assert run["platform"]
        assert "backends_silent" in run


def test_a_missing_artifact_is_a_503_that_says_so(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """There is no fallback table (D-082), so the honest answer is that reliability is unknown.

    A 200 with an empty body would render as "nothing measured yet", which is the one reading
    that must not be available to a deployment whose numbers cannot be justified.
    """
    sign_in(client)

    def unavailable() -> None:
        raise CalibrationError("calibration.json is missing")

    monkeypatch.setattr("codesheriff_api.calibration.active_artifact", unavailable)

    response = client.get("/calibration")

    assert response.status_code == 503
    assert "calibration.json is missing" in response.json()["detail"]
