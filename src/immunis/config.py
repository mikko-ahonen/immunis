"""Repository-supplied policy.

Everything a generic scanner cannot know about your project lives here: which
distribution names are yours rather than the public index's, how many recipients
a secrets store is supposed to have, which scans a pipeline owes.

Read from `immunis.toml`, or from `[tool.immunis]` in `pyproject.toml` when
that file is absent. tomllib is stdlib, so config costs no dependency.

Design rule: **a check that needs configuration does nothing without it.** A
scanner that fires on repositories which never opted in gets switched off in a
week, and then it is gating nothing at all.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILENAME = "immunis.toml"
PYPROJECT = "pyproject.toml"

DEFAULT_MIN_SOPS_RECIPIENTS = 2


@dataclass(frozen=True)
class WorkflowScans:
    """A CI workflow and the scan markers it is expected to contain."""

    path: str
    markers: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    # Distribution names served from a private index. Naming one here is what
    # lets immunis tell "you pinned your own package against pypi.org" apart
    # from "you pinned a public package", which is not inferable from the file.
    private_distributions: frozenset[str] = frozenset()
    # Minimum age recipients in a sops config. Two is the usual shape — an
    # admin/recovery key plus the key the workload actually decrypts with — so
    # one means either the workload cannot decrypt or the store is a single
    # lost key from unrecoverable.
    min_sops_recipients: int = DEFAULT_MIN_SOPS_RECIPIENTS
    required_workflow_scans: tuple[WorkflowScans, ...] = ()
    fail_on: str | None = None
    # Paths never walked, on top of the built-in vendor/build directories.
    exclude: tuple[str, ...] = ()
    source: str | None = field(default=None, compare=False)

    @property
    def configured(self) -> bool:
        return self.source is not None


def _normalise(name: str) -> str:
    """PEP 503 style: distribution names compare case- and separator-blind."""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def _from_mapping(raw: dict, source: str) -> Config:
    scans = []
    for entry in raw.get("required_workflow_scans", ()) or ():
        path = entry.get("path")
        markers = tuple(entry.get("markers", ()) or ())
        if path and markers:
            scans.append(WorkflowScans(path=path, markers=markers))
    return Config(
        private_distributions=frozenset(
            _normalise(n) for n in raw.get("private_distributions", ()) or ()
        ),
        min_sops_recipients=int(
            raw.get("min_sops_recipients", DEFAULT_MIN_SOPS_RECIPIENTS)
        ),
        required_workflow_scans=tuple(scans),
        fail_on=raw.get("fail_on"),
        exclude=tuple(raw.get("exclude", ()) or ()),
        source=source,
    )


def load(root: Path) -> Config:
    """Config for a checkout, or an unconfigured Config when there is none.

    `immunis.toml` wins over `[tool.immunis]`; a repository that has both is
    almost certainly mid-migration, and picking the dedicated file makes which
    one is live obvious from the filename.
    """
    dedicated = root / CONFIG_FILENAME
    if dedicated.is_file():
        with dedicated.open("rb") as fh:
            return _from_mapping(tomllib.load(fh) or {}, CONFIG_FILENAME)

    pyproject = root / PYPROJECT
    if pyproject.is_file():
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh) or {}
        section = (data.get("tool") or {}).get("immunis")
        if section is not None:
            return _from_mapping(section, f"{PYPROJECT} [tool.immunis]")

    return Config()
