"""immunis — find a Python repository's dependency-confusion exposure.

The attack this exists for: pip resolves a requirement across *every* index it
can see and takes the highest version it finds. Point it at a private index
with `--extra-index-url` and the public index is still in scope, so anyone who
registers one of your internal distribution names on pypi.org with a higher
version number gets their code installed instead of yours — in your build, with
your credentials in the environment.

The defence is an install where the private index is the ONLY index in scope,
and the checks here find the places a repository has quietly given that up.

Deliberately NOT what this does: known-bad detection. Secrets in git history,
CVEs in dependencies, CVEs in built images — gitleaks, pip-audit and trivy
answer those and answer them better. immunis answers "is this repository's
package resolution still shaped the way you think it is?", which those tools
cannot see.
"""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("immunis")
except PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
