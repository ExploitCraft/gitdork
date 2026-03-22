"""
Comprehensive tests for wifi-passview v1.1.0.
Covers models, Linux parser, platform dispatch, reporters, and bug fixes.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import sys

from wifi_passview.models import ScanResult, WifiProfile


# ── WifiProfile ───────────────────────────────────────────────────────────────

class TestWifiProfile:
    def test_has_password_true(self):
        assert WifiProfile(ssid="Net", password="secret").has_password is True

    def test_has_password_false_none(self):
        assert WifiProfile(ssid="Net").has_password is False

    def test_has_password_false_empty(self):
        assert WifiProfile(ssid="Net", password="").has_password is False

    def test_redact_long(self):
        p = WifiProfile(ssid="Net", password="mysecretpass")
        r = p.redact()
        assert r.password.startswith("my")
        assert r.password.endswith("ss")
        assert "***" in r.password

    def test_redact_short(self):
        r = WifiProfile(ssid="Net", password="ab").redact()
        assert r.password == "****"

    def test_redact_none(self):
        assert WifiProfile(ssid="Net").redact().password is None

    def test_redact_preserves_original(self):
        p = WifiProfile(ssid="Net", password="original")
        p.redact()
        assert p.password == "original"

    def test_redact_preserves_ssid(self):
        p = WifiProfile(ssid="MyNet", password="pass1234")
        assert p.redact().ssid == "MyNet"

    def test_redact_exactly_5_chars(self):
        r = WifiProfile(ssid="Net", password="abcde").redact()
        assert r.password.startswith("ab")
        assert r.password.endswith("de")

    def test_fields_default_none(self):
        p = WifiProfile(ssid="X")
        assert p.auth_type is None
        assert p.band is None
        assert p.auto_connect is None
        assert p.last_connected is None
        assert p.interface is None


# ── ScanResult ────────────────────────────────────────────────────────────────

class TestScanResult:
    def _make(self, *passwords):
        return ScanResult(profiles=[
            WifiProfile(ssid=f"Net{i}", password=p)
            for i, p in enumerate(passwords)
        ])

    def test_total(self):
        assert self._make("p1", None, "p3").total == 3

    def test_with_password(self):
        assert self._make("p1", None, "p3").with_password == 2

    def test_without_password(self):
        assert self._make("p1", None, "p3").without_password == 1

    def test_empty(self):
        r = ScanResult()
        assert r.total == 0
        assert r.with_password == 0
        assert r.without_password == 0

    def test_errors_default_empty(self):
        assert ScanResult().errors == []


# ── Linux: NetworkManager parser ──────────────────────────────────────────────

class TestLinuxNMParser:
    def test_basic_wpa(self, tmp_path):
        from wifi_passview.platforms.linux import _parse_nm_file
        conf = tmp_path / "Home.nmconnection"
        conf.write_text(textwrap.dedent("""
            [connection]
            id=Home
            type=wifi
            autoconnect=yes

            [wifi]
            ssid=HomeNetwork

            [wifi-security]
            key-mgmt=wpa-psk
            psk=supersecret123
        """))
        result = ScanResult(platform="linux")
        _parse_nm_file(conf, result)
        assert len(result.profiles) == 1
        assert result.profiles[0].ssid == "HomeNetwork"
        assert result.profiles[0].password == "supersecret123"
        assert result.profiles[0].auth_type == "wpa-psk"
        assert result.profiles[0].auto_connect is True

    def test_autoconnect_no(self, tmp_path):
        from wifi_passview.platforms.linux import _parse_nm_file
        conf = tmp_path / "Net.nmconnection"
        conf.write_text(textwrap.dedent("""
            [connection]
            id=Net
            type=wifi
            autoconnect=no

            [wifi]
            ssid=TestNet
        """))
        result = ScanResult(platform="linux")
        _parse_nm_file(conf, result)
        assert result.profiles[0].auto_connect is False

    def test_no_wifi_section_skipped(self, tmp_path):
        from wifi_passview.platforms.linux import _parse_nm_file
        conf = tmp_path / "vpn.nmconnection"
        conf.write_text("[connection]\nid=VPN\ntype=vpn\n")
        result = ScanResult(platform="linux")
        _parse_nm_file(conf, result)
        assert len(result.profiles) == 0

    def test_no_ssid_skipped(self, tmp_path):
        from wifi_passview.platforms.linux import _parse_nm_file
        conf = tmp_path / "nosid.nmconnection"
        conf.write_text("[wifi]\nmode=infrastructure\n")
        result = ScanResult(platform="linux")
        _parse_nm_file(conf, result)
        assert len(result.profiles) == 0

    def test_open_network_no_password(self, tmp_path):
        from wifi_passview.platforms.linux import _parse_nm_file
        conf = tmp_path / "open.nmconnection"
        conf.write_text(textwrap.dedent("""
            [wifi]
            ssid=OpenCafe
        """))
        result = ScanResult(platform="linux")
        _parse_nm_file(conf, result)
        assert result.profiles[0].password is None

    def test_quoted_ssid_stripped(self, tmp_path):
        from wifi_passview.platforms.linux import _parse_nm_file
        conf = tmp_path / "q.nmconnection"
        conf.write_text('[wifi]\nssid="QuotedName"\n')
        result = ScanResult(platform="linux")
        _parse_nm_file(conf, result)
        assert result.profiles[0].ssid == "QuotedName"

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not supported on Windows")
    def test_permission_denied_adds_error(self, tmp_path):
        from wifi_passview.platforms.linux import _parse_nm_file
        conf = tmp_path / "secret.nmconnection"
        conf.write_text("[wifi]\nssid=X\n")
        conf.chmod(0o000)
        result = ScanResult(platform="linux")
        _parse_nm_file(conf, result)
        assert len(result.profiles) == 0
        assert any("Permission denied" in e for e in result.errors)
        conf.chmod(0o644)  # restore for cleanup


# ── Linux: wpa_supplicant parser ──────────────────────────────────────────────

class TestLinuxWPAParser:
    def test_basic_wpa_network(self, tmp_path):
        from wifi_passview.platforms import linux
        conf = tmp_path / "wpa_supplicant.conf"
        conf.write_text(textwrap.dedent("""
            network={
                ssid="CoffeeShop"
                psk="latteplease"
                key_mgmt=WPA-PSK
            }
        """))
        original = linux.WPA_SUPPLICANT_PATHS
        linux.WPA_SUPPLICANT_PATHS = [conf]
        result = ScanResult(platform="linux")
        linux._try_wpa_supplicant(result)
        linux.WPA_SUPPLICANT_PATHS = original
        assert any(p.ssid == "CoffeeShop" and p.password == "latteplease"
                   for p in result.profiles)

    def test_open_network(self, tmp_path):
        from wifi_passview.platforms import linux
        conf = tmp_path / "wpa.conf"
        conf.write_text('network={\n    ssid="OpenNet"\n    key_mgmt=NONE\n}\n')
        original = linux.WPA_SUPPLICANT_PATHS
        linux.WPA_SUPPLICANT_PATHS = [conf]
        result = ScanResult(platform="linux")
        linux._try_wpa_supplicant(result)
        linux.WPA_SUPPLICANT_PATHS = original
        guest = next(p for p in result.profiles if p.ssid == "OpenNet")
        assert guest.password is None
        assert guest.auth_type == "OPEN"

    def test_multiple_networks(self, tmp_path):
        from wifi_passview.platforms import linux
        conf = tmp_path / "wpa.conf"
        conf.write_text(textwrap.dedent("""
            network={ ssid="Net1" psk="pass1" }
            network={ ssid="Net2" psk="pass2" }
        """))
        original = linux.WPA_SUPPLICANT_PATHS
        linux.WPA_SUPPLICANT_PATHS = [conf]
        result = ScanResult(platform="linux")
        linux._try_wpa_supplicant(result)
        linux.WPA_SUPPLICANT_PATHS = original
        assert len(result.profiles) == 2

    def test_no_file_skipped(self):
        from wifi_passview.platforms import linux
        original = linux.WPA_SUPPLICANT_PATHS
        linux.WPA_SUPPLICANT_PATHS = [Path("/nonexistent/wpa.conf")]
        result = ScanResult(platform="linux")
        linux._try_wpa_supplicant(result)
        linux.WPA_SUPPLICANT_PATHS = original
        assert len(result.profiles) == 0


# ── Bug fix: PermissionError on iterdir ──────────────────────────────────────

class TestPermissionErrorBugFix:
    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not supported on Windows")
    def test_nm_iterdir_permission_error_adds_error(self, tmp_path):
        """v1.1.0 fix: PermissionError on nm_dir.iterdir() must not crash."""
        from wifi_passview.platforms import linux
        nm_dir = tmp_path / "system-connections"
        nm_dir.mkdir()
        nm_dir.chmod(0o000)

        original = linux.NM_PATHS
        linux.NM_PATHS = [nm_dir]
        result = ScanResult(platform="linux")
        linux._try_networkmanager(result)
        linux.NM_PATHS = original
        nm_dir.chmod(0o755)  # restore

        assert any("Permission denied" in e for e in result.errors)
        assert len(result.profiles) == 0

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not supported on Windows")
    def test_nm_iterdir_permission_error_does_not_raise(self, tmp_path):
        """Must not raise PermissionError — just adds to errors."""
        from wifi_passview.platforms import linux
        nm_dir = tmp_path / "system-connections"
        nm_dir.mkdir()
        nm_dir.chmod(0o000)

        original = linux.NM_PATHS
        linux.NM_PATHS = [nm_dir]
        result = ScanResult(platform="linux")
        try:
            linux._try_networkmanager(result)
        except PermissionError:
            pytest.fail("PermissionError was not caught — v1.1.0 bug still present")
        finally:
            linux.NM_PATHS = original
            nm_dir.chmod(0o755)

    def test_nonexistent_nm_dir_skipped(self):
        from wifi_passview.platforms import linux
        original = linux.NM_PATHS
        linux.NM_PATHS = [Path("/nonexistent/nm-connections")]
        result = ScanResult(platform="linux")
        linux._try_networkmanager(result)
        linux.NM_PATHS = original
        assert len(result.errors) == 0


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDeduplication:
    def test_duplicate_ssids_deduped(self, tmp_path):
        from wifi_passview.platforms import linux
        conf1 = tmp_path / "a.nmconnection"
        conf2 = tmp_path / "b.nmconnection"
        for c in [conf1, conf2]:
            c.write_text('[wifi]\nssid=SameNet\n[wifi-security]\npsk=pass\n')

        original = linux.NM_PATHS
        linux.NM_PATHS = [tmp_path]
        result = linux.get_profiles()
        linux.NM_PATHS = original

        ssids = [p.ssid for p in result.profiles]
        assert ssids.count("SameNet") == 1


# ── Reporters ─────────────────────────────────────────────────────────────────

class TestJSONReporter:
    def _result(self):
        return ScanResult(platform="linux", profiles=[
            WifiProfile(ssid="Net1", password="pass1", auth_type="WPA-PSK"),
            WifiProfile(ssid="Net2", password=None),
        ])

    def test_to_dict_structure(self):
        from wifi_passview.reporters.json_report import to_dict
        data = to_dict(self._result())
        assert "platform" in data
        assert "summary" in data
        assert "profiles" in data
        assert data["summary"]["total"] == 2

    def test_to_dict_with_password(self):
        from wifi_passview.reporters.json_report import to_dict
        data = to_dict(self._result())
        assert data["summary"]["with_password"] == 1

    def test_redact_in_json(self):
        from wifi_passview.reporters.json_report import to_dict
        data = to_dict(self._result(), redact=True)
        p = next(p for p in data["profiles"] if p["ssid"] == "Net1")
        assert p["password"] != "pass1"
        assert p["password"] is not None
        assert "*" in p["password"]

    def test_write_to_file(self, tmp_path):
        from wifi_passview.reporters.json_report import write
        out = tmp_path / "out.json"
        write(self._result(), out)
        data = json.loads(out.read_text())
        assert data["summary"]["total"] == 2


class TestCSVReporter:
    def _result(self):
        return ScanResult(platform="linux", profiles=[
            WifiProfile(ssid="Net1", password="pass1"),
        ])

    def test_csv_has_header(self):
        from wifi_passview.reporters.csv_report import to_csv_string
        csv = to_csv_string(self._result())
        assert "ssid" in csv
        assert "password" in csv

    def test_csv_has_data(self):
        from wifi_passview.reporters.csv_report import to_csv_string
        csv = to_csv_string(self._result())
        assert "Net1" in csv
        assert "pass1" in csv

    def test_csv_redact(self):
        from wifi_passview.reporters.csv_report import to_csv_string
        csv = to_csv_string(self._result(), redact=True)
        assert "pass1" not in csv

    def test_write_to_file(self, tmp_path):
        from wifi_passview.reporters.csv_report import write
        out = tmp_path / "out.csv"
        write(self._result(), out)
        assert out.exists()
        assert "Net1" in out.read_text()


# ── Platform dispatch ─────────────────────────────────────────────────────────

class TestPlatformDispatch:
    def test_unsupported_platform_returns_error(self, monkeypatch):
        import sys
        import wifi_passview.platforms as plat
        monkeypatch.setattr(sys, "platform", "haiku")
        result = plat.get_profiles()
        assert len(result.errors) > 0
        assert "Unsupported" in result.errors[0]
