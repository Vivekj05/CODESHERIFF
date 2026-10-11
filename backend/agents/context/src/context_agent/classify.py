"""Which CWE a missing control is about, if any.

The division of labour in this agent is the point of it. **Which controls this repository
applies is learned** from merged code (`regression.py`); **which of them are authorization
controls is fixed** here. Making both halves learned would mean inferring a CWE from a name
the agent has never been told the meaning of; making both halves fixed would produce a second
rule engine with a hard-coded guard list, which is `structural.taint` with worse coverage.

`context.rag` reports **CWE-862 and CWE-639 only**, and the narrowness is deliberate three
times over.

`IN_SCOPE_CWES` is a closed set and `Evidence.detection` requires a CWE, so a control that
maps to nothing here cannot be reported at all — which is the mechanism that keeps a mined
convention from becoming a finding. A repository where every merged view calls `escape()` has
established a real convention, and a unit that drops it has really regressed; it is still not
this witness's finding, because escaping is not authorization.

These are also the two CWEs the taint engine holds no rules for whatsoever, which is what
`CLAUDE.md` means by the authorization cases existing "to prove heterogeneity". Reporting
CWE-89 from a missing `execute(query, params)` convention would put this agent in the
structural witness's territory, reading the same signal by a weaker method — and correlated
witnesses are what the four-agent argument is built to avoid.

Matching is on `Control.simple_name`, the last dotted segment, and by substring. A repository
names its guard `require_owner`, `assert_owner` or `_check_owner_or_403`, and a rule that
demanded an exact name would be a rule about one codebase's spelling.
"""

from __future__ import annotations

from codesheriff_contracts import IN_SCOPE_CWES
from context_agent.controls import Control

CWE_MISSING_AUTHORIZATION = "CWE-862"
CWE_OWNERSHIP_BYPASS = "CWE-639"

OWNERSHIP_TOKENS: frozenset[str] = frozenset(
    {
        "owner",
        "owned",
        "belongs_to",
        "same_user",
        "is_mine",
        "tenant",
    }
)
"""CWE-639: the check is that *this* object belongs to *this* caller.

Tested before the authorization tokens, because ownership is the more specific claim. A guard
named `require_owner` would match neither list's intent if `require` decided the answer.
"""

AUTHORIZATION_TOKENS: frozenset[str] = frozenset(
    {
        "admin",
        "staff",
        "superuser",
        "permission",
        "authorize",
        "authorise",
        "authz",
        "login_required",
        "require_login",
        "requires_login",
        "require_auth",
        "requires_auth",
        "require_role",
        "has_role",
        "scope",
        "acl",
        "can_",
        "has_access",
        "access_control",
        "check_access",
    }
)
"""CWE-862: the caller is not entitled to reach this operation at all.

Every token is specific enough to be about entitlement. There is deliberately no bare
`access` — it matches `log_access` and `access_count`, neither of which enforces anything —
and no bare `check`, `verify`, `validate` or `require`, which are the four most common verbs
in any codebase and would turn `validate_payload` into an authorization control.

`rate_limit`, `throttle` and `audit_log` are absent rather than excluded. They are genuine
conventions that a repository establishes and a new endpoint can genuinely break; they are
availability and observability, and mapping either to CWE-862 would be a false positive
dressed as thoroughness. `cwe-918-link-preview` carries a history that fires exactly this
trap, on both twins, so the omission is measured rather than trusted.
"""


def cwe_for(control: Control) -> str | None:
    """The in-scope CWE a missing `control` would be about, or None.

    None is the common answer and is not a failure: most of what a function calls is not a
    security control, and this is the filter that stops mined conventions from becoming
    findings.
    """
    name = control.simple_name.lower()

    for token in OWNERSHIP_TOKENS:
        if token in name:
            return CWE_OWNERSHIP_BYPASS if CWE_OWNERSHIP_BYPASS in IN_SCOPE_CWES else None

    for token in AUTHORIZATION_TOKENS:
        if token in name:
            return CWE_MISSING_AUTHORIZATION if CWE_MISSING_AUTHORIZATION in IN_SCOPE_CWES else None

    return None


COVERED_CWES: frozenset[str] = frozenset({CWE_MISSING_AUTHORIZATION, CWE_OWNERSHIP_BYPASS}) & (
    IN_SCOPE_CWES
)
"""What this agent's SILENCE is allowed to speak to (D-006).

Exactly the CWEs `cwe_for` can return. A witness whose silence covered more than it can
detect would suppress other witnesses' findings on CWEs it never looked for — the failure
D-006 exists to prevent, described there for the taint engine and CWE-862, and reintroduced
here the moment this set and that function disagree. `test_covered_cwes_matches_the_classifier`
holds them together.
"""
