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

# A generated-file manifest, if something generates files into this
# repository: a JSON object of {path: sha256} or a sha256sum-format file.
# The sensor records each listed file's listed digest next to its actual
# one, so a hand-edited generated file is a fact (tag `hand-edited`).
generated_manifest = ".generated.json"

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

## The fact artifact

Besides the findings, every scan writes a **fact artifact**: what the
repository contains, with no judgement attached. A consumer that keeps
history and evaluates rules of its own reads this instead of the findings,
and a rule can then be changed without rescanning anything.

```bash
immunis scan . --fail-on none            # judge nothing here; the consumer does
immunis scan . --base "$BASE_SHA"        # include the redacted diff of a change
immunis report tmp/immunis/scan.json --report https://consumer.example
```

The artifact lands in `tmp/immunis/scan.json` (`--artifact FILE` to move it,
`--no-artifact` to skip it) and is POSTed to `<URL>/api/v1/scans` with
`--report`. It is described by `src/immunis/artifact.schema.json`, versioned
additively: within a major, new kinds, fields and tags only. What is in it:

| collector | emits |
|---|---|
| `repository` | the repository (forge, owner, name, default branch, file count) and the commit (sha, parents, subject, when) |
| `files` | one record per tracked file: path, size, sha256, kind, executable; tags `tracked`, `generated`, `vendored` |
| `python-deps` | one per requirements line: name, specifier, extras, which file, `pinned`/`unpinned`, `public-file`/`private-file`, `private` when the name is in your config |
| `indexes` | every index URL in build inputs, **credentials redacted**, with `union` for `--extra-index-url` and `credentialed` when something was there |
| `workflows` | CI workflows, their jobs with the `needs` graph, and their steps, with the scanner tool a step runs when recognisable, `disabled` for commented-out or `if: false` steps and `soft-fail` for `continue-on-error`; `run:` text is digested, never copied |
| `sops` | each secrets store with its recipient count and public recipient ids |
| `env` | each `.env` with its **key names** and which keys assign a credential-looking value; values never leave the collector |
| `suppressions` | every `immunis: allow <id>` as a fact — the consumer honours it, the sensor no longer filters on it |
| `diff` | with `--base`: the unified diff, redacted and capped at 512 KiB with dropped files listed |

| `local-checks` | every executable under `.immunis/checks/`, run out of process with the checkout as working directory: exit code, duration, output digest, its sha256 and the digest listed for it in `.immunis/checks/SHA256SUMS`, so a `modified` or `unlisted` check is a fact; findings it prints as a JSON list become `local_finding` records |

### Local checks

Checks that are yours and not the scanner's live in the repository, under
`.immunis/checks/`. Each is an executable; the sensor runs it and records
what it said, never what it meant. A check may print a JSON list of
findings on stdout, each with `rule_id`, `severity`, `message` and
optionally `path` and `line`; a non-zero exit means the check could not
run and is recorded as `failed`. Whatever generates the checks can write
`SHA256SUMS` beside them (the `sha256sum` format), and a check whose digest
differs from its listed one is tagged `modified`. No configuration names
the checks: the directory is the list.

A collector that fails is listed in the artifact's `scan.failed` with a
reason; absence is never silent. The scanner's own findings ride along as
`third_party_finding` records with `tool = "immunis"`, so a consumer can
treat them like gitleaks' or trivy's until it has rules of its own.

## In CI

```yaml
- name: Dependency-confusion scan
  run: |
    python -m venv /tmp/immunis && /tmp/immunis/bin/pip install -q immunis
    /tmp/immunis/bin/immunis scan . --fail-on high
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` the scan could
not run. `--json` writes the findings to stdout; `--report URL` POSTs the fact
artifact to a consumer (bearer from `IMMUNIS_TOKEN`), best-effort — a consumer
being down must not turn your pipeline red, so the exit code comes from the
findings alone.

## No runtime dependencies

This is a security property, not minimalism. A scanner is often installed with
the private index as the only index in scope — `pip install --index-url
<private> --no-deps immunis` — precisely so that no public package can
substitute itself for the tool that checks for substitution. A dependency here
would force `--extra-index-url` back into that install line. Config is read
with stdlib `tomllib`.

## License

MIT.
