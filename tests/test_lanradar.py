"""Offline unit tests for lanradar (no network access needed)."""
import json
from argparse import Namespace

import pytest

import lanradar as lr


# --------------------------------------------------------------------------
# target parsing
# --------------------------------------------------------------------------

def test_parse_single_ip():
    ips = lr.parse_targets(["192.168.1.10"])
    assert [str(x) for x in ips] == ["192.168.1.10"]


def test_parse_cidr_excludes_network_and_broadcast():
    ips = lr.parse_targets(["192.168.1.0/24"])
    assert len(ips) == 254
    assert str(ips[0]) == "192.168.1.1"
    assert str(ips[-1]) == "192.168.1.254"


def test_parse_cidr_32_and_31():
    assert [str(x) for x in lr.parse_targets(["10.0.0.1/32"])] == ["10.0.0.1"]
    assert [str(x) for x in lr.parse_targets(["10.0.0.0/31"])] == ["10.0.0.0", "10.0.0.1"]


def test_parse_range_full():
    ips = lr.parse_targets(["192.168.1.10-20"])
    assert [str(x) for x in ips] == [
        "192.168.1.%d" % i for i in range(10, 21)]


def test_parse_range_shorthand_last_octet():
    ips = lr.parse_targets(["192.168.1.1-3"])
    assert [str(x) for x in ips] == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_parse_multiple_specs_dedup_sorted():
    ips = lr.parse_targets(["192.168.1.0/30", "192.168.1.2"])
    # /30 hosts are .1 and .2 (.0 network, .3 broadcast)
    assert [str(x) for x in ips] == ["192.168.1.1", "192.168.1.2"]


def test_parse_bad_specs():
    with pytest.raises(ValueError):
        lr.parse_targets(["not-an-ip"])
    with pytest.raises(ValueError):
        lr.parse_targets(["192.168.1.50-10"])
    with pytest.raises(ValueError):
        lr.parse_targets(["192.168.1.1-"])


def test_parse_range_too_large():
    with pytest.raises(ValueError):
        lr.parse_targets(["10.0.0.1-10.1.0.2"])  # 65537 addresses


def test_netmask_bits():
    # helper used inside detect_local_subnet logic
    assert sum(bin(int(o)).count("1") for o in "255.255.255.0".split(".")) == 24
    assert sum(bin(int(o)).count("1") for o in "255.255.0.0".split(".")) == 16


# --------------------------------------------------------------------------
# ARP parsers
# --------------------------------------------------------------------------

LINUX_ARP = """192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
192.168.1.20 dev eth0 lladdr 11:22:33:44:55:66 STALE
fe80::1234 dev eth0 lladdr 99:88:77:66:55:44 REACHABLE
"""

MACOS_ARP = """? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
? (192.168.1.30) at (incomplete) on en0 ifscope [ethernet]
192.168.1.40 at 11:22:33:44:55:66 on en0 ifscope permanent [ethernet]
"""

WINDOWS_ARP = """
Interface: 192.168.1.5 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.50          11-22-33-44-55-66     static
  incomplete            00-00-00-00-00-00     dynamic
"""


def test_arp_parse_linux():
    assert lr._norm_mac("AA-BB-CC-DD-EE-01") == "aa:bb:cc:dd:ee:01"
    table = _parse_linux_arp(LINUX_ARP)
    assert table["192.168.1.1"] == "aa:bb:cc:dd:ee:01"
    assert table["192.168.1.20"] == "11:22:33:44:55:66"
    assert "fe80::1234" not in table  # IPv6 line ignored


def test_arp_parse_macos():
    table = _parse_macos_arp(MACOS_ARP)
    assert table["192.168.1.1"] == "aa:bb:cc:dd:ee:01"
    assert table["192.168.1.40"] == "11:22:33:44:55:66"
    assert "192.168.1.30" not in table  # (incomplete)


def test_arp_parse_windows():
    table = _parse_windows_arp(WINDOWS_ARP)
    assert table["192.168.1.1"] == "aa:bb:cc:dd:ee:01"
    assert table["192.168.1.50"] == "11:22:33:44:55:66"
    assert len(table) == 2


def _parse_linux_arp(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = __import__("re").match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+" + lr._MAC_RE,
            line, __import__("re").IGNORECASE)
        if m:
            out[m.group(1)] = lr._norm_mac(m.group(2))
    return out


def _parse_macos_arp(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = __import__("re").match(
            r"^\s*(?:\S+\s+)?\(?"
            r"(\d+\.\d+\.\d+\.\d+)\)?\s+at\s+" + lr._MAC_RE, line,
            __import__("re").IGNORECASE)
        if m:
            out[m.group(1)] = lr._norm_mac(m.group(2))
    return out


def _parse_windows_arp(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = __import__("re").match(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", line,
            __import__("re").IGNORECASE)
        if m:
            out[m.group(1)] = lr._norm_mac(m.group(2))
    return out


# --------------------------------------------------------------------------
# OUI
# --------------------------------------------------------------------------

def test_vendor_lookup_mini():
    assert lr.vendor_for("aa:bb:cc:dd:ee:ff", lr.MINI_OUI) == ""
    assert lr.vendor_for("00:50:56:12:34:56", lr.MINI_OUI) == "VMware"
    assert lr.vendor_for("b8:27:eb:aa:bb:cc", lr.MINI_OUI) == "Raspberry Pi Trading"
    assert lr.vendor_for("", lr.MINI_OUI) == ""


IEEE_OUI_SAMPLE = """\
# OUI Assignment
# AA-BB-CC     Organization
00-50-56\t    VMware Inc.
B8-27-EB\t    Raspberry Pi Trading
52-54-00\t    Red Hat, Inc.
garbage line without tab
"""


def test_parse_oui_file():
    db = lr._parse_oui_file(IEEE_OUI_SAMPLE)
    assert db["00:50:56"] == "VMware Inc."
    assert db["b8:27:eb"] == "Raspberry Pi Trading"
    assert db["52:54:00"] == "Red Hat, Inc."
    assert len(db) == 3


def test_load_oui_mini():
    db, note = lr.load_oui("mini")
    assert "VMware" in db.values()
    assert "mini" in note


def test_load_oui_custom_file(tmp_path):
    f = tmp_path / "oui.txt"
    f.write_text(IEEE_OUI_SAMPLE, encoding="utf-8")
    db, note = lr.load_oui(str(f))
    assert db["00:50:56"] == "VMware Inc."
    assert "custom" in note


def test_load_oui_missing_file_falls_back(tmp_path):
    db, note = lr.load_oui(str(tmp_path / "nope.txt"))
    assert lr.MINI_OUI["00:50:56"] in db.values()
    assert "fell back" in note


# --------------------------------------------------------------------------
# state file
# --------------------------------------------------------------------------

def _dev(ip, **kw):
    d = lr.Device(ip=ip, alive=True)
    for k, v in kw.items():
        setattr(d, k, v)
    return d


def test_state_roundtrip(tmp_path):
    p = str(tmp_path / "state.json")
    devs = [_dev("192.168.1.10", mac="aa:bb:cc:dd:ee:01", vendor="Test"),
            _dev("192.168.1.11")]
    lr.save_state(p, devs)
    loaded = lr.load_state(p)
    assert set(loaded) == {"192.168.1.10", "192.168.1.11"}
    assert loaded["192.168.1.10"]["vendor"] == "Test"


def test_state_missing_file():
    assert lr.load_state("/nonexistent/state.json") == {}


def test_diff_marks_new_and_gone(tmp_path):
    p = str(tmp_path / "s.json")
    lr.save_state(p, [_dev("192.168.1.10"), _dev("192.168.1.20")])
    prev = lr.load_state(p)
    now = [_dev("192.168.1.10"), _dev("192.168.1.30")]
    lr.diff_events(now, prev)
    events = {d.ip: d.event for d in now}
    assert events["192.168.1.10"] == ""
    assert events["192.168.1.30"] == "new"
    gone = [d for d in now if d.event == "gone"]
    assert [d.ip for d in gone] == ["192.168.1.20"]
    assert gone[0].alive is False


def test_first_seen_preserved(tmp_path):
    p = str(tmp_path / "s.json")
    lr.save_state(p, [_dev("192.168.1.10", first_seen="2026-01-01T00:00:00")])
    prev = lr.load_state(p)
    assert prev["192.168.1.10"]["first_seen"] == "2026-01-01T00:00:00"


# --------------------------------------------------------------------------
# ports / services
# --------------------------------------------------------------------------

def test_port_str():
    assert lr._port_str([22, 80, 443]) == "22/ssh, 80/http, 443/https"
    assert lr._port_str([]) == ""
    s = lr._port_str([1, 2, 3, 4, 5, 6, 7, 8])
    assert s.endswith("+2")


# --------------------------------------------------------------------------
# json / csv
# --------------------------------------------------------------------------

def test_to_json_serializable():
    devs = [_dev("192.168.1.10", mac="aa:bb:cc:dd:ee:01", vendor="VMware",
                 ports=[22, 80], gateway=True, first_seen="x", last_seen="y")]
    doc = lr.to_json(devs, "192.168.1.0/24", {"probed": 254, "arp_entries": 3,
                                              "icmp_up": 5, "with_ports": 1,
                                              "elapsed": 1.2})
    assert doc["subnet"] == "192.168.1.0/24"
    assert doc["devices"][0]["gateway"] is True
    json.dumps(doc)


def test_to_rows():
    rows = lr.to_rows([_dev("1.2.3.4", mac="aa:bb:cc:dd:ee:01", ports=[80])])
    assert rows[0][0] == "1.2.3.4"
    assert rows[0][4] == "80"


# --------------------------------------------------------------------------
# argv preparation
# --------------------------------------------------------------------------

def test_prepare_argv_interleaved():
    got = lr._prepare_argv(["192.168.1.0/24", "--rdns", "10.0.0.5", "-t", "2"])
    assert got[-2:] == ["192.168.1.0/24", "10.0.0.5"]
    assert got[:3] == ["--rdns", "-t", "2"]


def test_prepare_argv_ddash():
    got = lr._prepare_argv(["--ports", "80,443", "--", "-weird", "1.2.3.4"])
    assert got[-2:] == ["-weird", "1.2.3.4"]


def test_prepare_argv_no_options():
    assert lr._prepare_argv(["a", "b"]) == ["a", "b"]


# --------------------------------------------------------------------------
# device model
# --------------------------------------------------------------------------

def test_device_defaults():
    d = lr.Device(ip="10.0.0.1")
    assert d.alive is False
    assert d.ports == []
    assert d.event == ""
