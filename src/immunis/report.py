"""Sending a scan somewhere that keeps history.

stdlib urllib rather than httpx — see the `dependencies = []` note in
pyproject.toml. The POST is best-effort by design: a collector being down must
not turn every pipeline red. A scan that FINDS something still fails the run
through the exit code; losing the report costs history, not the gate.

The bearer is read from the environment, never a flag: a token in argv is a
token in every process listing and CI log.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request

from . import __version__

REPORT_PATH = "/api/reports"           # the findings payload (legacy consumers)
SCANS_PATH = "/api/v1/scans"            # the fact artifact (see collectors.py)
TIMEOUT_SECONDS = 15
TOKEN_ENV = "IMMUNIS_TOKEN"


def payload(project: str, ref: str | None, findings) -> dict:
    return {
        "project": project,
        "ref": ref,
        "scanner": "immunis",
        "scanner_version": __version__,
        "findings": [f.as_dict() for f in findings],
    }


def send(base_url: str, token: str, body: dict, path: str = REPORT_PATH) -> tuple[bool, str]:
    """POST a body. Returns (ok, human-readable status); never raises."""
    url = base_url.rstrip("/") + path
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"immunis/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return True, f"reported to {url} ({response.status})"
    except urllib.error.HTTPError as exc:
        # The body can carry the collector's reason; the token is never echoed.
        return False, f"report rejected: HTTP {exc.code} {exc.reason}"
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        return False, f"could not reach {url}: {exc}"


def send_artifact(base_url: str, token: str, artifact: dict) -> tuple[bool, str]:
    """POST the fact artifact to the consumer's ingest endpoint."""
    return send(base_url, token, artifact, SCANS_PATH)
