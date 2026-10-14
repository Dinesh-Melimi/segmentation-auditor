import json

from segaudit.core import covers, findings, lateral_paths

R = json.load(open("samples/rules.json"))
P = json.load(open("samples/policy.json"))
F = findings(R, P)


def msgs(rid):
    return [m for r, _, m in F if r == rid]


def test_rdp_from_internet_is_critical():
    assert ("20", "critical", "RDP exposed to the internet") in F


def test_it_to_scada_boundary_flagged():
    assert any("prohibited boundary" in m for m in msgs("40"))


def test_any_service_between_zones():
    assert any("any-service" in m for m in msgs("30"))


def test_shadowed_rule_detected():
    assert any("shadowed by rule 30" in m for m in msgs("35"))


def test_zero_hit_rule():
    assert any("zero hits" in m for m in msgs("50"))


def test_lateral_path_users_to_scada():
    assert lateral_paths(R, "users", "scada") == ["users", "servers", "scada"]


def test_covers_subnet_logic():
    assert covers(R[2], R[3]) and not covers(R[3], R[2])
