"""Firewall rule analysis: risky rules, shadowed rules and segmentation-policy violations.

Rules are vendor-neutral dicts (export from Palo Alto, Fortinet, Azure NSG, AWS SG and map fields):
  {id, src_zone, dst_zone, src, dst, service, action, enabled, hits}
Policy says which zone pairs may talk and on which services:
  {"allow": [{"from": "users", "to": "dmz", "services": ["tcp/443"]}], "deny_always": [["it", "scada"]]}
"""
import ipaddress

RISKY_SERVICES = {"tcp/3389": "RDP", "tcp/22": "SSH", "tcp/445": "SMB", "tcp/23": "Telnet",
                  "tcp/502": "Modbus", "udp/161": "SNMP", "tcp/1433": "MSSQL"}


def _net(v):
    return ipaddress.ip_network("0.0.0.0/0" if v == "any" else v, strict=False)


def covers(a, b):
    """True if rule a matches every packet rule b matches."""
    return ((a["src_zone"] in ("any", b["src_zone"])) and (a["dst_zone"] in ("any", b["dst_zone"]))
            and _net(b["src"]).subnet_of(_net(a["src"])) and _net(b["dst"]).subnet_of(_net(a["dst"]))
            and a["service"] in ("any", b["service"]))


def findings(rules, policy):
    out = []
    allowed = {(p["from"], p["to"]): set(p["services"]) for p in policy.get("allow", [])}
    never = {tuple(x) for x in policy.get("deny_always", [])}
    active = [r for r in rules if r.get("enabled", True)]

    for i, r in enumerate(active):
        rid, pair = r["id"], (r["src_zone"], r["dst_zone"])
        if r["action"] != "allow":
            continue
        if r["src"] == "any" and r["dst"] == "any" and r["service"] == "any":
            out.append((rid, "critical", "any-any-any allow rule"))
        elif r["src_zone"] == "internet" and r["service"] in RISKY_SERVICES:
            out.append((rid, "critical", f"{RISKY_SERVICES[r['service']]} exposed to the internet"))
        if pair in never or (pair[::-1] in never):
            out.append((rid, "critical", f"crosses prohibited boundary {pair[0]} -> {pair[1]}"))
        elif pair[0] != pair[1]:
            ok = allowed.get(pair)
            if ok is None:
                out.append((rid, "high", f"zone pair {pair[0]} -> {pair[1]} not in segmentation policy"))
            elif r["service"] != "any" and r["service"] not in ok:
                out.append((rid, "medium", f"service {r['service']} not approved for {pair[0]} -> {pair[1]}"))
            elif r["service"] == "any":
                out.append((rid, "high", f"any-service allow between {pair[0]} -> {pair[1]}"))
        if r.get("hits", 1) == 0:
            out.append((rid, "low", "allow rule has zero hits; candidate for removal"))
        for earlier in active[:i]:
            if covers(earlier, r):
                out.append((rid, "medium", f"shadowed by rule {earlier['id']} and never evaluated"))
                break
    return out


def lateral_paths(rules, start, target, max_hops=4):
    """Zones reachable from `start` via allowed rules; returns a path to `target` if one exists."""
    edges = {}
    for r in rules:
        if r.get("enabled", True) and r["action"] == "allow":
            edges.setdefault(r["src_zone"], set()).add(r["dst_zone"])
    frontier, seen = [[start]], {start}
    while frontier:
        path = frontier.pop(0)
        if path[-1] == target:
            return path
        if len(path) > max_hops:
            continue
        for nxt in sorted(edges.get(path[-1], ())):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(path + [nxt])
    return None
