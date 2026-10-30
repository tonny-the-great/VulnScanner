"""Scanner command builders must apply the script/template safety policy for every profile."""

from types import SimpleNamespace

import pytest

from app.core.exceptions import ValidationError
from app.scanning.adapters.nmap import command_builder
from app.scanning.adapters.nmap.adapter import NmapAdapter
from app.scanning.adapters.nmap.command_builder import (
    OS_DETECTION_SKIPPED_WARNING,
    build_nmap_command,
)
from app.scanning.adapters.nuclei.adapter import NucleiAdapter
from app.scanning.adapters.testssl.command_builder import build_testssl_command
from app.scanning.profiles import DEFAULT_PROFILES

ALWAYS_EXCLUDED = "not (dos or brute or fuzzer or broadcast or external"


def _script_arg(cmd: list[str]) -> str | None:
    return next((arg for arg in cmd if arg.startswith("--script=")), None)


@pytest.fixture
def unprivileged(monkeypatch):
    monkeypatch.setattr(command_builder.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(
        command_builder, "get_settings", lambda: SimpleNamespace(NMAP_PRIVILEGED=False)
    )


NMAP_PROFILES = [
    p for p in DEFAULT_PROFILES if p["config_json"].get("nmap", {}).get("enabled", True)
]


@pytest.mark.parametrize("profile", NMAP_PROFILES, ids=[p["name"] for p in NMAP_PROFILES])
def test_every_nmap_profile_excludes_dangerous_categories(profile, tmp_path, unprivileged):
    config = {**profile["config_json"], "is_intrusive": profile["is_intrusive"]}
    cmd = NmapAdapter().build_command(["192.0.2.1"], config, str(tmp_path / "x"))
    script = _script_arg(cmd)
    assert script is not None
    assert ALWAYS_EXCLUDED in script
    assert "--script-timeout=10m" in cmd
    if profile["is_intrusive"]:
        assert "or intrusive)" not in script
    else:
        assert script.endswith("or external or intrusive)")
    if profile["name"] == "intrusive_active":
        # The intrusive profile runs every vuln script, not only the safe ones.
        assert script == (
            "--script=(default or (discovery and safe) or vuln) and not "
            "(dos or brute or fuzzer or broadcast or external)"
        )


def test_missing_is_intrusive_is_strict(tmp_path, unprivileged):
    profile = next(p for p in DEFAULT_PROFILES if p["name"] == "intrusive_active")
    cmd = NmapAdapter().build_command(["192.0.2.1"], profile["config_json"], str(tmp_path / "x"))
    assert _script_arg(cmd).endswith("or intrusive)")


def test_script_expression_is_a_single_argument(unprivileged):
    cmd = build_nmap_command(["192.0.2.1"], {"scripts": ["default", "vuln", "default"]}, "out.xml")
    assert _script_arg(cmd) == (
        "--script=(default or (vuln and safe)) and not "
        "(dos or brute or fuzzer or broadcast or external or intrusive)"
    )


@pytest.mark.parametrize("scripts", [["all"], ["default", "brute"], "vuln", [None]])
def test_unknown_script_sets_are_rejected(scripts):
    with pytest.raises(ValidationError):
        build_nmap_command(["192.0.2.1"], {"scripts": scripts}, "out.xml")


def test_no_scripts_means_no_script_arguments():
    cmd = build_nmap_command(["192.0.2.1"], {"scripts": []}, "out.xml")
    assert _script_arg(cmd) is None
    assert not any(arg.startswith("--script-timeout") for arg in cmd)


@pytest.mark.parametrize(
    "value, expected",
    [(30, "--host-timeout=30m"), (0, None), (241, None), ("5", None), (True, None)],
)
def test_host_timeout(value, expected):
    cmd = build_nmap_command(["192.0.2.1"], {"host_timeout_minutes": value}, "out.xml")
    found = [arg for arg in cmd if arg.startswith("--host-timeout")]
    assert found == ([expected] if expected else [])


def test_os_detection_skipped_without_privileges(tmp_path, unprivileged):
    base = str(tmp_path / "scan")
    adapter = NmapAdapter()
    cmd = adapter.build_command(["192.0.2.1"], {"nmap": {"os_detection": True}}, base)
    assert "-O" not in cmd
    (tmp_path / "scan.xml").write_text("<nmaprun></nmaprun>", encoding="utf-8")
    result = adapter.parse_output(base, 0, "", "", 0)
    assert result.warnings == [OS_DETECTION_SKIPPED_WARNING]

    # A later build without warnings removes the stale sidecar.
    adapter.build_command(["192.0.2.1"], {"nmap": {"os_detection": False}}, base)
    assert not (tmp_path / "scan.warnings.json").exists()
    assert adapter.parse_output(base, 0, "", "", 0).warnings == []


def test_os_detection_as_root(monkeypatch):
    monkeypatch.setattr(command_builder.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        command_builder, "get_settings", lambda: SimpleNamespace(NMAP_PRIVILEGED=False)
    )
    warnings: list[str] = []
    cmd = build_nmap_command(["192.0.2.1"], {"os_detection": True}, "out.xml", warnings)
    assert "-O" in cmd
    assert "--privileged" not in cmd
    assert warnings == []


def test_os_detection_with_configured_privileges(monkeypatch):
    monkeypatch.setattr(command_builder.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(
        command_builder, "get_settings", lambda: SimpleNamespace(NMAP_PRIVILEGED=True)
    )
    cmd = build_nmap_command(["192.0.2.1"], {"os_detection": True}, "out.xml")
    assert "-O" in cmd
    assert "--privileged" in cmd


def test_host_discovery_flags():
    assert "-Pn" in build_nmap_command(["192.0.2.1"], {}, "out.xml")
    assert "-Pn" not in build_nmap_command(["192.0.2.1"], {"host_discovery": True}, "out.xml")
    assert "-Pn" not in build_nmap_command(["192.0.2.0/28"], {}, "out.xml")


def test_mixed_address_families_rejected():
    with pytest.raises(ValidationError):
        build_nmap_command(["192.0.2.1", "2001:db8::1"], {}, "out.xml")


def _etags(cmd: list[str]) -> str:
    return cmd[cmd.index("-etags") + 1]


def test_nuclei_excluded_tags(tmp_path):
    adapter = NucleiAdapter()
    base = str(tmp_path / "n")
    assert (
        _etags(adapter.build_command(["https://example.test"], {"nuclei": {}}, base))
        == "dos,fuzz,intrusive"
    )
    assert (
        _etags(
            adapter.build_command(
                ["https://example.test"], {"nuclei": {}, "is_intrusive": True}, base
            )
        )
        == "dos,fuzz"
    )


def test_testssl_rejects_multiple_targets_and_ranges():
    with pytest.raises(ValidationError, match="one target"):
        build_testssl_command(["192.0.2.1", "192.0.2.2"], {}, "out.json")
    with pytest.raises(ValidationError, match="address ranges"):
        build_testssl_command(["192.0.2.0/28"], {}, "out.json")
    assert build_testssl_command(["https://example.test"], {}, "out.json")[-1] == "example.test:443"
