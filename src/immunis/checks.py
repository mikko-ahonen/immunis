"""The checks.

Each is a function taking (Repo, Config) and yielding Findings, registered in
CHECKS at the bottom. Adding one means writing the function and appending it;
there is no plugin machinery on purpose — the set is small and worth reading
top to bottom.

Two rules hold for everything here:

  * A check that needs configuration does nothing without it. Firing on a
    repository that never opted in is how a scanner gets switched off.
  * No overlap with gitleaks, pip-audit or trivy. They answer "is anything here
    known-bad?" and answer it better; these answer "is package resolution still
    shaped the way you think?", which they cannot see.
"""

from __future__ import annotations

import re
from pathlib import Path

from .finding import Finding
from .repo import Repo

# A requirement line's distribution name: up to the first version specifier,
# extra, marker, or comment.
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[\[<>=!~;#].*)?$")

# A URL carrying credentials in its userinfo, captured as
# (whole, user, password) so the password can be judged separately.
_CREDENTIALED_URL = re.compile(
    r"https?://(?P<user>[^/\s:@]+):(?P<password>[^/\s@]+)@[^\s\"']+"
)

# A userinfo password that is obviously not a password. Documentation and
# templates describe this URL shape constantly — `https://reader:<token>@...`
# in a comment is a description of the hazard, not an instance of it, and a
# scanner that cannot tell the difference gets switched off by the first team
# that writes an honest README.
_PLACEHOLDER_PASSWORD = re.compile(
    r"""^(?:
          <[^>]*>              # <token>, <password>, <REDACTED>
        | \$\{?[A-Za-z_][^}]*\}?  # $TOKEN, ${TOKEN}
        | %\(?[A-Za-z_]\w*\)?s?   # %(token)s, %s
        | \{\{?[A-Za-z_][^}]*\}?\}? # {token}, {{ token }}
        | \*+ | x+ | \.\.\.       # ***, xxx, ...
        | token | password | secret | apikey | api_key | credential
        | changeme | placeholder | redacted
      )$""",
    re.IGNORECASE | re.VERBOSE,
)

# KEY=value where KEY smells like a credential and value is a real literal —
# not empty, not a ${...}/$VAR reference, not an obvious placeholder.
_SECRET_KEY = re.compile(
    r"^\s*(?:export\s+)?"
    r"([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|DSN|CREDENTIAL)[A-Z0-9_]*)"
    r"\s*=\s*(.+?)\s*$"
)
_PLACEHOLDER = re.compile(
    r"^(?:[\"']?\s*[\"']?|\$\{?[A-Za-z_].*|<.*>|x+|changeme|placeholder|todo"
    r"|your[-_].*|\.\.\.)$",
    re.IGNORECASE,
)

# Where index configuration hides. Not just Dockerfiles: pip reads pip.conf and
# setup.cfg too, and a union-mode index set there applies to every install in
# the environment without appearing in any requirements file.
_INDEX_CONFIG_NAMES = frozenset({
    "Dockerfile", "Containerfile", "requirements.txt", "requirements-dev.txt",
    "requirements-private.txt", "pip.conf", "pip.ini", "setup.cfg", "tox.ini",
})
_INDEX_CONFIG_SUFFIXES = frozenset({".yml", ".yaml", ".sh", ".toml", ".cfg"})

# Documentation is allowed to talk about the hazard without being the hazard.
_DOC_SUFFIXES = frozenset({".md", ".rst", ".txt"})


def _normalise(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(".", "-")


def _requirement_name(line: str) -> str | None:
    stripped = line.split("#", 1)[0].strip()
    if not stripped or stripped.startswith("-"):
        return None
    m = _REQ_NAME.match(stripped)
    return _normalise(m.group(1)) if m else None


def check_private_dep_in_public_requirements(repo, config):
    """A private distribution pinned in a public-index requirements file.

    requirements.txt is resolved against the public index. Anything of yours
    listed there either fails to resolve, or — worse — resolves against a
    package that is not yours.

    Needs `private_distributions` config; silent without it.
    """
    if not config.private_distributions:
        return
    for rel in repo.walk(names={"requirements.txt"}):
        for n, line in repo.lines(rel):
            name = _requirement_name(line)
            if name and name in config.private_distributions:
                yield Finding(
                    check="private-dep-in-public-requirements",
                    severity="high",
                    summary=(
                        f"{name} is a private distribution but is pinned in "
                        f"{rel}, which resolves against the public index"
                    ),
                    path=str(rel),
                    line=n,
                    detail={
                        "distribution": name,
                        "remedy": "pin it in a file installed against the "
                                  "private index alone",
                    },
                )


def check_pip_union_mode(repo, config):
    """`--extra-index-url` — pip resolving across indexes.

    This is the dependency-confusion mechanism itself: pip takes the highest
    version across every index in scope, so the public index can outrank the
    private one for a name you believe is yours. The fix is a two-step install
    with `--index-url` per step, never a union.
    """
    for rel in repo.walk():
        if rel.suffix in _DOC_SUFFIXES:
            continue
        if rel.name not in _INDEX_CONFIG_NAMES and rel.suffix not in _INDEX_CONFIG_SUFFIXES:
            continue
        for n, line in repo.lines(rel):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "--extra-index-url" in line or re.search(r"^\s*extra-index-url\s*=", line):
                yield Finding(
                    check="pip-union-mode",
                    severity="high",
                    summary="--extra-index-url puts pip in union mode across indexes",
                    path=str(rel),
                    line=n,
                    detail={
                        "remedy": "install public deps against the public "
                                  "index and private deps against the private "
                                  "index, each with --index-url",
                    },
                )


def check_credentials_in_url(repo, config):
    """A URL with user:password@ committed to the working tree.

    Index URLs carrying a read token are the usual shape. They belong wherever
    your secrets live and should reach the build as an injected value.
    """
    for rel in repo.walk():
        if rel.suffix in _DOC_SUFFIXES:
            continue
        for n, line in repo.lines(rel):
            for m in _CREDENTIALED_URL.finditer(line):
                if _PLACEHOLDER_PASSWORD.match(m.group("password")):
                    continue
                yield Finding(
                    check="credentials-in-url",
                    severity="critical",
                    summary="URL with embedded credentials committed to the tree",
                    path=str(rel),
                    line=n,
                    detail={"user": m.group("user"),
                            "remedy": "inject it at build/run time instead"},
                )


def check_plaintext_env_secret(repo, config):
    """A TRACKED .env assigning a real credential value.

    Tracked, not merely present: a gitignored deployment .env in a working copy
    is the system working as designed. See Repo._git_tracked.
    """
    for rel in repo.walk():
        name = rel.name
        if not (name == ".env" or name.startswith(".env.")):
            continue
        if name.endswith((".example", ".sample", ".template", ".dist")):
            continue
        for n, line in repo.lines(rel):
            m = _SECRET_KEY.match(line)
            if not m:
                continue
            value = m.group(2).strip().strip("\"'")
            if not value or _PLACEHOLDER.match(value):
                continue
            yield Finding(
                check="plaintext-env-secret",
                severity="critical",
                summary=f"{m.group(1)} has a literal value in {rel}",
                path=str(rel),
                line=n,
                detail={"key": m.group(1),
                        "remedy": "move it to your secrets store"},
            )


def check_sops_recipients(repo, config):
    """A sops store with too few age recipients.

    Self-gating: only runs where a sops store actually exists. The usual shape
    is two — an admin/recovery key plus the key the workload decrypts with — so
    one means either the workload cannot decrypt, or the store is one lost key
    away from unrecoverable. Configure `min_sops_recipients` to change that.
    """
    if not repo.exists("secrets.sops.json") and not repo.exists("secrets.sops.yaml"):
        return
    if not repo.exists(".sops.yaml"):
        yield Finding(
            check="sops-config-missing",
            severity="medium",
            summary="a sops store exists but .sops.yaml does not",
            path=".sops.yaml",
            detail={"remedy": "declare the store's recipients"},
        )
        return
    recipients = set(re.findall(r"age1[0-9a-z]{10,}", repo.read(".sops.yaml")))
    minimum = config.min_sops_recipients
    if len(recipients) < minimum:
        yield Finding(
            check="sops-single-recipient",
            severity="medium",
            summary=(f".sops.yaml names {len(recipients)} age recipient(s); "
                     f"expected at least {minimum}"),
            path=".sops.yaml",
            detail={"recipients": len(recipients), "expected": minimum},
        )


def check_required_workflow_scans(repo, config):
    """A CI workflow missing a scan the repository says it requires.

    Per-project skip flags are easy to set during a bad afternoon and easy to
    never unset. Declaring the expected markers in config turns "we meant to
    run trivy" into something checkable.

    Needs `required_workflow_scans` config; silent without it.
    """
    for spec in config.required_workflow_scans:
        parts = Path(spec.path).parts
        if not repo.exists(*parts):
            continue
        workflow = repo.read(*parts)
        for marker in spec.markers:
            if marker not in workflow:
                yield Finding(
                    check="required-scan-missing",
                    severity="medium",
                    summary=f"{spec.path} does not mention '{marker}'",
                    path=spec.path,
                    detail={"scan": marker},
                )


CHECKS = (
    check_private_dep_in_public_requirements,
    check_pip_union_mode,
    check_credentials_in_url,
    check_plaintext_env_secret,
    check_sops_recipients,
    check_required_workflow_scans,
)


def run(root: Path, config=None) -> list[Finding]:
    """Every check against `root`, in registration order, minus suppressions."""
    from .config import load

    config = config if config is not None else load(root)
    repo = Repo(root, exclude=config.exclude)
    return [f
            for check in CHECKS
            for f in check(repo, config)
            if not repo.suppressed(f)]
