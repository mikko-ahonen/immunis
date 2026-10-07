"""The command-line contract."""

import json

import pytest

from immunis.__main__ import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

UNION = "RUN pip install --extra-index-url $I acme\n"


def test_clean_repo_exits_zero(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    assert "no findings" in capsys.readouterr().out


def test_finding_at_threshold_exits_one(tmp_path):
    (tmp_path / "Dockerfile").write_text(UNION)
    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == EXIT_FINDINGS


def test_fail_on_none_reports_without_gating(tmp_path):
    (tmp_path / "Dockerfile").write_text(UNION)
    assert main(["scan", str(tmp_path), "--fail-on", "none"]) == EXIT_OK


def test_finding_below_threshold_does_not_gate(tmp_path):
    (tmp_path / "secrets.sops.json").write_text("{}")
    (tmp_path / ".sops.yaml").write_text("age: age1qqqqqqqqqqqqqqqqqqq\n")
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == EXIT_OK


def test_fail_on_from_config(tmp_path):
    """Config sets the gate when the flag doesn't."""
    (tmp_path / "immunis.toml").write_text('fail_on = "none"\n')
    (tmp_path / "Dockerfile").write_text(UNION)
    assert main(["scan", str(tmp_path)]) == EXIT_OK


def test_flag_overrides_config(tmp_path):
    (tmp_path / "immunis.toml").write_text('fail_on = "none"\n')
    (tmp_path / "Dockerfile").write_text(UNION)
    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == EXIT_FINDINGS


def test_missing_path_exits_two(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == EXIT_ERROR


def test_malformed_config_exits_two_rather_than_scanning(tmp_path, capsys):
    """Silently scanning with no policy looks exactly like a clean repo."""
    (tmp_path / "immunis.toml").write_text("not = = toml\n")
    assert main(["scan", str(tmp_path)]) == EXIT_ERROR
    assert "cannot read config" in capsys.readouterr().err


def test_project_defaults_to_directory_name(tmp_path, capsys):
    main(["scan", str(tmp_path), "--json"])
    assert json.loads(capsys.readouterr().out)["project"] == tmp_path.name


def test_json_output_is_machine_readable(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_text(UNION)
    main(["scan", str(tmp_path), "--project", "demo", "--ref", "abc123",
          "--fail-on", "none", "--json"])
    body = json.loads(capsys.readouterr().out)
    assert body["project"] == "demo"
    assert body["ref"] == "abc123"
    assert body["scanner"] == "immunis"
    assert body["findings"][0]["check"] == "pip-union-mode"


def test_report_without_token_warns_but_still_gates(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("IMMUNIS_TOKEN", raising=False)
    (tmp_path / "Dockerfile").write_text(UNION)
    assert main(["scan", str(tmp_path), "--report", "https://example.test"]) == EXIT_FINDINGS
    assert "IMMUNIS_TOKEN is unset" in capsys.readouterr().err


def test_unreachable_collector_does_not_change_the_gate(tmp_path, monkeypatch):
    """A collector being down must not turn a clean pipeline red."""
    monkeypatch.setenv("IMMUNIS_TOKEN", "t0ken")
    import immunis.__main__ as cli
    monkeypatch.setattr(cli, "send", lambda *a, **k: (False, "could not reach"))
    assert main(["scan", str(tmp_path), "--report", "https://example.test"]) == EXIT_OK


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "immunis" in capsys.readouterr().out


def test_version_comes_from_installed_metadata():
    from importlib.metadata import version
    import immunis
    assert immunis.__version__ == version("immunis")


def test_no_runtime_dependencies():
    """Load-bearing: CI installs this with the private index as the only one."""
    from importlib.metadata import requires
    runtime = [r for r in (requires("immunis") or []) if "extra ==" not in r]
    assert runtime == [], f"unexpected runtime dependencies: {runtime}"


def test_gate_without_token_holds(monkeypatch, capsys):
    monkeypatch.delenv("IMMUNIS_TOKEN", raising=False)
    assert main(["gate", "--subject", "abc", "--cadence", "change", "--report", "https://example.test"]) == EXIT_ERROR
    assert "holding" in capsys.readouterr().err


def _gate_answer(monkeypatch, status, body, text="gate answered"):
    import immunis.__main__ as cli
    calls = []

    def fake(base_url, token, subject, cadence, *, lifecycle="production", wait=0):
        calls.append((base_url, token, subject, cadence, lifecycle, wait))
        return status, body, text
    monkeypatch.setattr(cli, "ask_gate", fake)
    return calls


def test_gate_cleared_exits_zero(monkeypatch, capsys):
    monkeypatch.setenv("IMMUNIS_TOKEN", "t0ken")
    calls = _gate_answer(monkeypatch, 200, {"cleared": True, "required": [{"kind": "coverage", "status": "passing"}], "override": None})
    assert main(["gate", "--subject", "abc", "--cadence", "minor", "--wait", "30", "--report", "https://example.test"]) == EXIT_OK
    assert calls == [("https://example.test", "t0ken", "abc", "minor", "production", 30)]
    assert "cleared for minor" in capsys.readouterr().out


def test_gate_held_lists_the_kinds_not_green(monkeypatch, capsys):
    monkeypatch.setenv("IMMUNIS_TOKEN", "t0ken")
    _gate_answer(monkeypatch, 200, {"cleared": False, "required": [
        {"kind": "coverage", "status": "failing", "summary": "coverage 78.1% below 80%"},
        {"kind": "review", "status": "passing"},
        {"kind": "migrations", "status": "missing"}], "override": None,
        "pending_override": {"request": "request_1", "status": "open", "url": "https://brain.test/requests/request_1"}})
    assert main(["gate", "--subject", "abc", "--cadence", "change", "--lifecycle", "development",
                 "--report", "https://example.test"]) == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert "2 kind(s) not green" in err
    assert "override: a human may authorize https://brain.test/requests/request_1" in err
    assert "coverage: failing — coverage 78.1% below 80%" in err and "migrations: missing" in err
    assert "review" not in err


def test_gate_unknown_subject_or_unreachable_holds_with_two(monkeypatch, capsys):
    monkeypatch.setenv("IMMUNIS_TOKEN", "t0ken")
    _gate_answer(monkeypatch, 404, {"error": "unknown-subject", "detail": "nothing has been scanned for this subject"})
    assert main(["gate", "--subject", "abc", "--cadence", "change", "--report", "https://example.test"]) == EXIT_ERROR
    assert "nothing has been scanned" in capsys.readouterr().err
    _gate_answer(monkeypatch, None, None, "could not reach https://example.test/api/v1/gate")
    assert main(["gate", "--subject", "abc", "--cadence", "change", "--report", "https://example.test"]) == EXIT_ERROR
    assert "could not reach" in capsys.readouterr().err


def test_ask_gate_builds_the_query_and_never_raises(monkeypatch):
    import urllib.request
    from immunis.report import ask_gate
    seen = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"cleared": true, "required": []}'

    def fake_open(request, timeout):
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        seen["timeout"] = timeout
        return Resp()
    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    status, body, _ = ask_gate("https://c.example/", "tok", "abc", "minor", lifecycle="development", wait=20)
    assert (status, body) == (200, {"cleared": True, "required": []})
    assert seen["url"] == "https://c.example/api/v1/gate?subject=abc&cadence=minor&lifecycle=development&wait=20"
    assert seen["auth"] == "Bearer tok" and seen["timeout"] > 20

    def down(request, timeout):
        raise urllib.error.URLError("refused")
    import urllib.error
    monkeypatch.setattr(urllib.request, "urlopen", down)
    status, body, text = ask_gate("https://c.example", "tok", "abc", "minor")
    assert status is None and body is None and "could not reach" in text and "?" not in text
