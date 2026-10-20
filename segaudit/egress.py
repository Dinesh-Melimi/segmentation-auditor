"""Egress control audit: web proxy enforcement and data exfiltration paths.

Internal zones should reach the internet only through the web proxy, where
TLS inspection, URL filtering and DLP policies run. A firewall rule that lets
users or servers go straight out skips all of that. This module reads the
same vendor-neutral rule JSON and an "egress" block in the policy:

    "egress": {
      "proxy_zone": "proxy",
      "must_use_proxy": ["users", "servers"],
      "allowed_direct": [{"from": "servers", "services": ["udp/123"]}]
    }

Findings
  EG-01 critical  unrestricted outbound (service any) to the internet
  EG-02 high      web traffic (tcp/80, tcp/443) going direct, bypassing the proxy and its DLP
  EG-03 high      outbound file-transfer / tunnel services that DLP cannot inspect (FTP, SSH, SMB, RDP, Tor)
  EG-04 medium    other direct outbound not in the approved exception list (e.g. external DNS, SMTP)
  EG-05 medium    the proxy zone itself allows more than web ports out
"""
from __future__ import annotations

WEB = {"tcp/80", "tcp/443", "tcp/8080"}
EXFIL = {"tcp/20": "FTP data", "tcp/21": "FTP", "tcp/22": "SSH/SFTP", "tcp/445": "SMB", "tcp/3389": "RDP",
         "tcp/9001": "Tor", "tcp/9030": "Tor", "udp/1194": "OpenVPN", "tcp/1194": "OpenVPN"}


def egress_findings(rules, policy):
    eg = policy.get("egress") or {}
    proxy = eg.get("proxy_zone", "proxy")
    must = set(eg.get("must_use_proxy", []))
    allowed = {(a["from"], s) for a in eg.get("allowed_direct", []) for s in a.get("services", [])}
    out = []
    for r in rules:
        if r.get("action") != "allow" or r.get("dst_zone") not in ("internet", "any"):
            continue
        src, svc, rid = r["src_zone"], r["service"], r["id"]
        if src == "internet":
            continue
        if src == proxy:
            if svc == "any" or svc not in WEB:
                out.append((rid, "medium", f"proxy zone allows {svc} out; restrict it to web ports"))
            continue
        if svc == "any":
            out.append((rid, "critical", f"unrestricted outbound from {src} to the internet (any service)"))
        elif (src, svc) in allowed:
            continue
        elif svc in WEB and (src in must or src == "any"):
            out.append((rid, "high", f"{src} reaches the web directly on {svc}, bypassing the proxy and its DLP inspection"))
        elif svc in EXFIL:
            out.append((rid, "high", f"{src} can send data out over {EXFIL[svc]} ({svc}), which the proxy and DLP cannot inspect"))
        else:
            out.append((rid, "medium", f"direct outbound {svc} from {src} is not an approved exception"))
    return out
