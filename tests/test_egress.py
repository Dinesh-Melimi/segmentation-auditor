import json

from segaudit.cli import main
from segaudit.egress import egress_findings

R = json.load(open("samples/rules_egress.json"))
P = json.load(open("samples/policy_egress.json"))
F = {rid: (sev, msg) for rid, sev, msg in egress_findings(R, P)}


def test_proxy_path_is_clean():
    assert "200" not in F and "210" not in F


def test_direct_web_from_users_bypasses_proxy():
    assert F["220"][0] == "high" and "bypassing the proxy" in F["220"][1]


def test_ssh_out_is_an_exfil_channel():
    assert F["230"][0] == "high" and "SSH" in F["230"][1]


def test_approved_exception_not_flagged():
    assert "240" not in F            # NTP from servers is in allowed_direct


def test_external_dns_is_unapproved_direct_egress():
    assert F["250"][0] == "medium"


def test_any_service_outbound_is_critical():
    assert F["260"][0] == "critical"


def test_proxy_zone_limited_to_web_ports():
    assert F["270"][0] == "medium" and "proxy zone" in F["270"][1]


def test_cli_egress_flag(capsys):
    assert main(["--rules", "samples/rules_egress.json", "--policy", "samples/policy_egress.json", "--egress"]) == 1
    out = capsys.readouterr().out
    assert "bypassing the proxy" in out
