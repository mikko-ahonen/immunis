"""Config loading — where policy that a generic scanner cannot infer comes from."""

import pytest

from immunis.config import DEFAULT_MIN_SOPS_RECIPIENTS, load


def test_absent_config_is_unconfigured(tmp_path):
    cfg = load(tmp_path)
    assert not cfg.configured
    assert cfg.private_distributions == frozenset()
    assert cfg.min_sops_recipients == DEFAULT_MIN_SOPS_RECIPIENTS


def test_immunis_toml_is_read(tmp_path):
    (tmp_path / "immunis.toml").write_text(
        'private_distributions = ["Acme_Widgets"]\nfail_on = "critical"\n')
    cfg = load(tmp_path)
    assert cfg.configured
    assert cfg.private_distributions == frozenset({"acme-widgets"})
    assert cfg.fail_on == "critical"


def test_pyproject_tool_section_is_read(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\n\n[tool.immunis]\nprivate_distributions = ["a"]\n')
    cfg = load(tmp_path)
    assert cfg.private_distributions == frozenset({"a"})
    assert "pyproject.toml" in cfg.source


def test_pyproject_without_the_section_is_unconfigured(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    assert not load(tmp_path).configured


def test_dedicated_file_wins_over_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.immunis]\nprivate_distributions = ["from-pyproject"]\n')
    (tmp_path / "immunis.toml").write_text(
        'private_distributions = ["from-immunis-toml"]\n')
    assert load(tmp_path).private_distributions == frozenset({"from-immunis-toml"})


def test_workflow_scans_without_markers_are_dropped(tmp_path):
    (tmp_path / "immunis.toml").write_text(
        '[[required_workflow_scans]]\npath = "ci.yml"\n')
    assert load(tmp_path).required_workflow_scans == ()


def test_malformed_toml_raises(tmp_path):
    import tomllib
    (tmp_path / "immunis.toml").write_text("this is not = = toml\n")
    with pytest.raises(tomllib.TOMLDecodeError):
        load(tmp_path)
