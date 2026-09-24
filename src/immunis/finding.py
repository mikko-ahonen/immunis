"""Findings and the severity ordering that decides whether a run fails."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Ordered weakest → strongest. `--fail-on` names the weakest severity that
# still fails the run; "none" is the report-only setting and sorts above every
# real severity so nothing ever reaches it.
SEVERITIES = ("info", "low", "medium", "high", "critical")
FAIL_ON_CHOICES = SEVERITIES + ("none",)


def rank(severity: str) -> int:
    """Position in SEVERITIES; "none" ranks above everything."""
    if severity == "none":
        return len(SEVERITIES)
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        raise ValueError(
            f"unknown severity {severity!r} "
            f"(expected one of {', '.join(FAIL_ON_CHOICES)})"
        ) from None


@dataclass(frozen=True)
class Finding:
    """One violated invariant.

    `check` is a stable identifier: it is what suppressions name and what a
    downstream collector groups history by, so renaming one splits its
    timeline. Treat these as API, not as labels.
    """

    check: str
    severity: str
    summary: str
    # Repo-relative path the finding is anchored to, when there is one. A
    # finding about something ABSENT names the path it should have been at.
    path: str | None = None
    line: int | None = None
    # Free-form, per-check context a consumer can render without knowing the
    # check. `remedy` is conventional here: what to actually do about it.
    detail: dict = field(default_factory=dict)

    def __post_init__(self):
        rank(self.severity)  # reject a typo at construction, not at exit time

    def as_dict(self) -> dict:
        return asdict(self)


def gates(findings, fail_on: str) -> list[Finding]:
    """The findings at or above `fail_on` — the ones that fail the run."""
    threshold = rank(fail_on)
    return [f for f in findings if rank(f.severity) >= threshold]
