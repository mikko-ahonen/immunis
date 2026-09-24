"""Each check gets a repo that trips it and a repo that must not.

The clean cases carry more weight than the tripping ones: a scanner that fires
on everything gets switched off within a week, and then it gates nothing.
"""

import pytest

from immunis.finding import Finding, gates, rank

PRIVATE_CONFIG = 'private_distributions = ["acme-internal", "acme_widgets"]\n'


# --- severity ordering -----------------------------------------------------

def test_rank_orders_severities():
    assert rank("info") < rank("high") < rank("critical") < rank("none")


def test_unknown_severity_rejected_at_construction():
    with pytest.raises(ValueError):
        Finding(check="x", severity="catastrophic", summary="")


def test_gates_selects_at_or_above_threshold():
    findings = [Finding(check="a", severity="low", summary=""),
                Finding(check="b", severity="high", summary=""),
                Finding(check="c", severity="critical", summary="")]
    assert [f.check for f in gates(findings, "high")] == ["b", "c"]
    assert gates(findings, "none") == []


# --- private deps (config-driven) ------------------------------------------

def test_private_dep_in_requirements_is_flagged(repo):
    repo.write("immunis.toml", PRIVATE_CONFIG)
    repo.write("requirements.txt", "Django>=5.0\nacme-internal==1.2.3\n")
    found = repo.named("private-dep-in-public-requirements")
    assert len(found) == 1 and found[0].line == 2


def test_private_dep_check_is_silent_without_config(repo):
    """The property that makes this safe to run anywhere."""
    repo.write("requirements.txt", "acme-internal==1.2.3\n")
    assert repo.named("private-dep-in-public-requirements") == []


def test_distribution_names_compare_normalised(repo):
    """PEP 503: acme_widgets, Acme-Widgets and acme.widgets are one name."""
    repo.write("immunis.toml", PRIVATE_CONFIG)
    repo.write("requirements.txt", "Acme.Widgets==1.0\n")
    assert len(repo.named("private-dep-in-public-requirements")) == 1


def test_public_package_is_not_flagged(repo):
    repo.write("immunis.toml", PRIVATE_CONFIG)
    repo.write("requirements.txt", "requests==2.32.0\n")
    assert repo.named("private-dep-in-public-requirements") == []


def test_comment_is_not_a_pin(repo):
    repo.write("immunis.toml", PRIVATE_CONFIG)
    repo.write("requirements.txt", "# acme-internal is private\n")
    assert repo.named("private-dep-in-public-requirements") == []


# --- union mode (the flagship, needs no config) ----------------------------

def test_extra_index_url_in_dockerfile(repo):
    repo.write("Dockerfile", "RUN pip install --extra-index-url $IDX acme\n")
    assert len(repo.named("pip-union-mode")) == 1


def test_extra_index_url_in_pip_conf(repo):
    """pip.conf applies to every install in the environment, silently."""
    repo.write("pip.conf", "[global]\nextra-index-url = https://pypi.example/simple/\n")
    assert len(repo.named("pip-union-mode")) == 1


def test_extra_index_url_in_setup_cfg(repo):
    repo.write("setup.cfg", "[easy_install]\nextra-index-url = https://pypi.example/\n")
    assert len(repo.named("pip-union-mode")) == 1


def test_index_url_alone_is_clean(repo):
    """The correct shape must not be flagged, or nobody adopts the fix."""
    repo.write("Dockerfile", "RUN pip install --index-url $IDX --no-deps acme\n")
    assert repo.named("pip-union-mode") == []


def test_commented_extra_index_url_is_clean(repo):
    repo.write("Dockerfile", "# never use --extra-index-url here\n")
    assert repo.named("pip-union-mode") == []


def test_documentation_may_discuss_the_hazard(repo):
    repo.write("README.md", "Do not pass `--extra-index-url` to pip.\n")
    assert repo.named("pip-union-mode") == []


# --- credentials -----------------------------------------------------------

CREDENTIALED = "https://reader:" + "s3cr3t" + "@pypi.example.com/simple/"


def test_credentialed_url_is_flagged(repo):
    repo.write("setup.cfg", f"index-url = {CREDENTIALED}\n")
    found = repo.named("credentials-in-url")
    assert len(found) == 1 and found[0].severity == "critical"


def test_shell_expansion_in_userinfo_is_clean(repo):
    repo.write("setup.cfg", "index-url = https://reader:${TOKEN}@pypi.example.com/\n")
    assert repo.named("credentials-in-url") == []


# --- plaintext env ---------------------------------------------------------

def test_literal_secret_in_env(repo):
    repo.write(".env", "DEBUG=True\nSECRET_KEY=not-a-placeholder-value\n")
    found = repo.named("plaintext-env-secret")
    assert len(found) == 1 and found[0].detail["key"] == "SECRET_KEY"


def test_examples_and_placeholders_are_clean(repo):
    repo.write(".env.example", "SECRET_KEY=changeme\n")
    repo.write(".env", "SECRET_KEY=\nAPI_KEY=${VAULT_KEY}\nSENTRY_DSN=<your-dsn>\n")
    assert repo.named("plaintext-env-secret") == []


# --- sops (self-gating) ----------------------------------------------------

def test_single_recipient_store_is_flagged(repo):
    repo.write("secrets.sops.json", "{}")
    repo.write(".sops.yaml", "creation_rules:\n  - age: age1qqqqqqqqqqqqqqqqqqq\n")
    found = repo.named("sops-single-recipient")
    assert len(found) == 1 and found[0].detail["recipients"] == 1


def test_two_recipients_is_clean(repo):
    repo.write("secrets.sops.json", "{}")
    repo.write(".sops.yaml",
               "age: >-\n  age1qqqqqqqqqqqqqqqqqqq,\n  age1wwwwwwwwwwwwwwwwwww\n")
    assert repo.named("sops-single-recipient") == []


def test_min_recipients_is_configurable(repo):
    repo.write("immunis.toml", "min_sops_recipients = 3\n")
    repo.write("secrets.sops.json", "{}")
    repo.write(".sops.yaml",
               "age: >-\n  age1qqqqqqqqqqqqqqqqqqq,\n  age1wwwwwwwwwwwwwwwwwww\n")
    assert len(repo.named("sops-single-recipient")) == 1


def test_no_store_means_no_sops_findings(repo):
    repo.write("README.md", "nothing here\n")
    assert [f for f in repo.scan() if f.check.startswith("sops-")] == []


# --- required workflow scans (config-driven) -------------------------------

WORKFLOW_CONFIG = """
[[required_workflow_scans]]
path = ".github/workflows/ci.yml"
markers = ["gitleaks", "trivy"]
"""


def test_missing_required_scan_is_flagged(repo):
    repo.write("immunis.toml", WORKFLOW_CONFIG)
    repo.write(".github/workflows/ci.yml", "steps:\n  - run: gitleaks detect\n")
    found = repo.named("required-scan-missing")
    assert [f.detail["scan"] for f in found] == ["trivy"]


def test_all_required_scans_present_is_clean(repo):
    repo.write("immunis.toml", WORKFLOW_CONFIG)
    repo.write(".github/workflows/ci.yml",
               "steps:\n  - run: gitleaks detect\n  - run: trivy image x\n")
    assert repo.named("required-scan-missing") == []


def test_workflow_check_is_silent_without_config(repo):
    repo.write(".github/workflows/ci.yml", "steps:\n  - run: true\n")
    assert repo.named("required-scan-missing") == []


# --- suppression -----------------------------------------------------------

def test_suppression_on_the_same_line(repo):
    repo.write("Dockerfile",
               "RUN pip install --extra-index-url $I x  # immunis: allow pip-union-mode\n")
    assert repo.named("pip-union-mode") == []


def test_suppression_on_the_line_above(repo):
    repo.write("Dockerfile",
               "# immunis: allow pip-union-mode\nRUN pip install --extra-index-url $I x\n")
    assert repo.named("pip-union-mode") == []


def test_suppression_names_one_check_only(repo):
    repo.write("Dockerfile",
               "RUN pip install --extra-index-url $I x  # immunis: allow something-else\n")
    assert len(repo.named("pip-union-mode")) == 1


def test_there_is_no_blanket_allow(repo):
    repo.write("Dockerfile",
               "RUN pip install --extra-index-url $I x  # immunis: allow\n")
    assert len(repo.named("pip-union-mode")) == 1


def test_file_level_finding_is_suppressible_anywhere_in_the_file(repo):
    repo.write("secrets.sops.json", "{}")
    repo.write(".sops.yaml",
               "# immunis: allow sops-single-recipient\nage: age1qqqqqqqqqqqqqqqqqqq\n")
    assert repo.named("sops-single-recipient") == []


# --- whole-repo defaults ---------------------------------------------------

def test_empty_repo_has_no_findings(repo):
    assert repo.scan() == []


def test_vendor_directories_are_not_walked(repo):
    repo.write("node_modules/pkg/Dockerfile", "RUN pip install --extra-index-url $I x\n")
    repo.write(".venv/lib/Dockerfile", "RUN pip install --extra-index-url $I x\n")
    assert repo.scan() == []


def test_exclude_patterns_from_config(repo):
    repo.write("immunis.toml", 'exclude = ["fixtures/*"]\n')
    repo.write("fixtures/Dockerfile", "RUN pip install --extra-index-url $I x\n")
    assert repo.named("pip-union-mode") == []


# --- credential placeholders ------------------------------------------------
#
# Regression: scanning telamon's own projects.yaml produced three CRITICAL
# findings, all of them comments documenting the URL SHAPE
# (`https://reader:<token>@.../pypi/simple/`). Describing the hazard is not
# committing it, and a scanner that cannot tell the difference is one nobody
# leaves switched on.

@pytest.mark.parametrize("password", [
    "<token>", "<REDACTED>", "${TOKEN}", "$TOKEN", "%(token)s",
    "{{ token }}", "***", "xxxx", "...", "token", "PASSWORD", "changeme",
])
def test_placeholder_userinfo_is_not_a_credential(repo, password):
    repo.write("setup.cfg", f"index-url = https://reader:{password}@pypi.example/simple/\n")
    assert repo.named("credentials-in-url") == []


def test_placeholder_in_a_comment_is_clean(repo):
    repo.write("config.yaml",
               "# the URL `https://reader-user:<token>@host/pypi/simple/` is stored encrypted\n")
    assert repo.named("credentials-in-url") == []


def test_a_real_credential_next_to_a_placeholder_is_still_found(repo):
    """The placeholder rule must not become a way to hide a real one."""
    real = "https://u:" + "A1b2C3d4E5f6" + "@pypi.example/simple/"
    repo.write("setup.cfg", f"a = https://u:<token>@pypi.example/\nb = {real}\n")
    found = repo.named("credentials-in-url")
    assert len(found) == 1 and found[0].line == 2


# --- tracked vs merely present ---------------------------------------------
#
# Regression: scanning a real infra repo produced ~180 CRITICAL findings, all
# of them gitignored deployment .env files that were never committed. "A secret
# is in this repository" and "a secret is on this disk" are different claims,
# and only the first one is this tool's business. Noise like that does not just
# annoy — it buries the one real finding underneath it.

import subprocess


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args],
                   check=True, capture_output=True)


def _git_repo(root):
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "test")


def test_gitignored_env_is_not_flagged(repo):
    _git_repo(repo.root)
    repo.write(".gitignore", ".env\n")
    repo.write(".env", "SECRET_KEY=a-real-looking-value\n")
    _git(repo.root, "add", "-A")
    _git(repo.root, "commit", "-qm", "init")
    assert repo.named("plaintext-env-secret") == []


def test_tracked_env_is_still_flagged(repo):
    _git_repo(repo.root)
    repo.write(".env", "SECRET_KEY=a-real-looking-value\n")
    _git(repo.root, "add", "-A")
    _git(repo.root, "commit", "-qm", "init")
    assert len(repo.named("plaintext-env-secret")) == 1


def test_untracked_new_file_is_not_flagged(repo):
    """Not yet added is not committed."""
    _git_repo(repo.root)
    repo.write("README.md", "x\n")
    _git(repo.root, "add", "README.md")
    _git(repo.root, "commit", "-qm", "init")
    repo.write("Dockerfile", "RUN pip install --extra-index-url $I x\n")
    assert repo.named("pip-union-mode") == []


def test_non_git_directory_still_scans(repo):
    """An unpacked tarball deserves a scan; degrade to the filesystem."""
    repo.write("Dockerfile", "RUN pip install --extra-index-url $I x\n")
    assert len(repo.named("pip-union-mode")) == 1
