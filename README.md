# immunis

Find a Python repository's **dependency-confusion exposure**.

```bash
pip install immunis
immunis scan .
```

## The problem

pip resolves a requirement across *every* index it can see and takes the
highest version it finds. Point it at a private index with `--extra-index-url`
and the public index is still in scope — so anyone who registers one of your
internal distribution names on pypi.org, with a higher version number, gets
their code installed instead of yours. In your build. With your credentials in
the environment.

The defence is an install where the private index is the **only** index in
scope:

```dockerfile
# public dependencies, public index
RUN pip install -r requirements.txt

# yours, private index only — no union, nothing to outrank
RUN pip install --index-url "$PRIVATE_INDEX" --no-deps -r requirements-private.txt
```

immunis finds the places a repository has quietly given that up.

## What it checks

| check | needs config | what it means |
|---|---|---|
| `pip-union-mode` | no | `--extra-index-url` in a Dockerfile, requirements file, `pip.conf`, `setup.cfg` or CI workflow — pip is resolving across indexes |
| `credentials-in-url` | no | a `https://user:token@…` URL committed to the tree |
| `plaintext-env-secret` | no | a **tracked** `.env` assigning a real credential value |
| `private-dep-in-public-requirements` | yes | one of your private distributions pinned in a file resolved against the public index |
| `sops-single-recipient` | no | a sops store with fewer recipients than it needs to be both usable and recoverable |
| `required-scan-missing` | yes | a CI workflow missing a scan the repository says it requires |

**Not** what this does: known-bad detection. Secrets in git history, CVEs in
dependencies, CVEs in built images — gitleaks, pip-audit and trivy answer those
and answer them better. immunis answers *"is this repository's package
resolution still shaped the way you think it is?"*, which those tools cannot
see.

## Tracked, not merely present

Findings come from files **git tracks**. A gitignored deployment `.env` sitting
in a working copy is the system working as designed, and reporting it as a
committed credential is noise of the worst kind — alarming, wrong, and
guaranteed to bury the real finding underneath it. Outside a git repository
immunis falls back to walking the filesystem, because an unpacked tarball still
deserves a scan.

## Configuration

Optional, in `immunis.toml` or `[tool.immunis]` in `pyproject.toml`:

```toml
# Which distribution names are yours. immunis cannot infer this, and without it
# the private-dependency check stays silent.
private_distributions = ["acme-internal", "acme-widgets"]

fail_on = "high"          # default; "none" reports without gating
min_sops_recipients = 2
exclude = ["tests/fixtures/*"]

[[required_workflow_scans]]
path = ".github/workflows/ci.yml"
markers = ["gitleaks", "trivy"]
```

**A check that needs configuration does nothing without it.** A scanner that
fires on repositories which never opted in gets switched off in a week, and
then it is gating nothing at all.

## Suppressing a finding

```python
# immunis: allow credentials-in-url — fixture for the test that asserts we catch these
INDEX = "https://reader:abc123@pypi.example.com/simple/"
```

Covers that check on the same line or the line below; for a finding that names
a path but no line, anywhere in that file. The check id is required — there is
deliberately no blanket `allow`, because a repository should not be able to
switch the scanner off by accident, and a suppression you have to name is one a
reviewer can argue with.

Prefer restructuring over suppressing. immunis's own credential fixture is
assembled from pieces rather than waived.

## In CI

```yaml
- name: Dependency-confusion scan
  run: |
    python -m venv /tmp/immunis && /tmp/immunis/bin/pip install -q immunis
    /tmp/immunis/bin/immunis scan . --fail-on high
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` the scan could
not run. `--json` writes the scan to stdout; `--report URL` POSTs it to a
collector (bearer from `IMMUNIS_TOKEN`), best-effort — a collector being down
must not turn your pipeline red, so the exit code comes from the findings
alone.

## No runtime dependencies

This is a security property, not minimalism. A scanner is often installed with
the private index as the only index in scope — `pip install --index-url
<private> --no-deps immunis` — precisely so that no public package can
substitute itself for the tool that checks for substitution. A dependency here
would force `--extra-index-url` back into that install line. Config is read
with stdlib `tomllib`.

## License

MIT.
