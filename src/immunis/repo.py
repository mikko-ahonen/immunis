"""Walking a checkout, and the inline suppression syntax."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

# Never walked: vendored code, build output, virtualenvs, and the git object
# store (history is gitleaks' job; we judge the working tree).
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "dist",
    "build", "site-packages", ".terraform", ".eggs",
})

# `immunis: allow <check-id>` in a comment suppresses that check on the same
# line, or on the line immediately below — so the comment can sit above the
# offending line and carry its reason with it.
#
# The check id is REQUIRED. There is deliberately no blanket `allow`: a
# repository should not be able to switch the scanner off by accident, and a
# suppression you have to name is one a reviewer can argue with.
_SUPPRESSION = re.compile(r"immunis:\s*allow\s+([a-z0-9][a-z0-9-]*)")


class Repo:
    """A checkout, plus the small amount of caching the checks share."""

    def __init__(self, root: Path, exclude=(), tracked_only: bool = True):
        self.root = root
        self._exclude = tuple(exclude)
        self._suppressions: dict[str, dict[int, set[str]]] = {}
        self._tracked = self._git_tracked() if tracked_only else None

    def _git_tracked(self) -> frozenset[str] | None:
        """Paths git tracks, or None when that can't be determined.

        This is the difference between "a secret is in this repository" and "a
        secret is on this disk". A deployment .env sitting gitignored in a
        working copy is the system working as designed; reporting it as a
        committed credential is noise of the worst kind — alarming, wrong, and
        guaranteed to bury the real finding underneath it.

        Degrades to walking the filesystem when git is absent or the directory
        is not a repository, because an unpacked tarball still deserves a scan.
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), "ls-files", "-z"],
                capture_output=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        names = result.stdout.decode("utf-8", "replace").split("\0")
        tracked = frozenset(n for n in names if n)
        # An empty repository and "git told us nothing useful" look the same
        # here; treat the latter as unknown rather than as "nothing to scan".
        return tracked or None

    # -- paths -------------------------------------------------------------

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    def exists(self, *parts: str) -> bool:
        return self.path(*parts).exists()

    def read(self, *parts: str) -> str:
        """Contents, or "" when absent or not decodable as text."""
        try:
            return self.path(*parts).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""

    def _excluded(self, rel: Path) -> bool:
        if any(part in SKIP_DIRS for part in rel.parts):
            return True
        if self._tracked is not None and str(rel) not in self._tracked:
            return True
        return any(rel.match(pattern) for pattern in self._exclude)

    def walk(self, suffixes=None, names=None):
        """Repo-relative paths of regular files, skipping vendor/build dirs."""
        for p in sorted(self.root.rglob("*")):
            if not p.is_file() or p.is_symlink():
                continue
            rel = p.relative_to(self.root)
            if self._excluded(rel):
                continue
            if suffixes is not None and p.suffix not in suffixes:
                continue
            if names is not None and p.name not in names:
                continue
            yield rel

    def lines(self, rel: Path):
        """(1-based line number, text) for a repo-relative path."""
        try:
            text = (self.root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        for n, line in enumerate(text.splitlines(), start=1):
            yield n, line

    # -- suppression -------------------------------------------------------

    def suppressions(self, rel: Path) -> dict[int, set[str]]:
        """{line number: {check id, ...}} for a path.

        A comment on line N covers N and N+1. Line 0 is the file-level bucket,
        holding every suppression in the file — used for findings that name a
        path but no line.
        """
        key = str(rel)
        cached = self._suppressions.get(key)
        if cached is not None:
            return cached
        found: dict[int, set[str]] = {}
        for n, line in self.lines(rel):
            for check in _SUPPRESSION.findall(line):
                found.setdefault(n, set()).add(check)
                found.setdefault(n + 1, set()).add(check)
                found.setdefault(0, set()).add(check)
        self._suppressions[key] = found
        return found

    def suppressed(self, finding) -> bool:
        """Whether an inline allow covers this finding."""
        if not finding.path:
            return False
        table = self.suppressions(Path(finding.path))
        # A finding with no line is file-level: any suppression naming its
        # check anywhere in that file covers it.
        return finding.check in table.get(finding.line or 0, set())
