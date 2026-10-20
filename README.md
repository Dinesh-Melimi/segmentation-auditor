# Segmentation Auditor

Segmentation lives in two places that drift apart: the design document that says which zones may talk, and the firewall rulebase that actually decides. This tool checks one against the other, which is the core of firewall rule validation and a large part of proving Zero Trust segmentation to an auditor.

It flags:

- **Any-any-any allows** and **risky services exposed to the internet** (RDP, SMB, SSH, Telnet, Modbus, SNMP)
- **Prohibited boundaries**, e.g. any rule from IT into SCADA/OT
- **Zone pairs or services not in the approved policy**
- **Shadowed rules** that can never match, and **zero-hit allows** to clean up
- **Lateral-movement paths** between zones by chaining allowed rules (`users -> servers -> scada`)

Rules are vendor-neutral JSON, so exports from Palo Alto, Fortinet, Azure NSG or AWS Security Groups map onto the same fields.

## Run

```bash
python -m segaudit.cli --rules samples/rules.json --policy samples/policy.json
```

```
[CRITICAL] rule 20: RDP exposed to the internet
[CRITICAL] rule 40: crosses prohibited boundary servers -> scada
[HIGH    ] rule 30: any-service allow between users -> servers
[MEDIUM  ] rule 35: shadowed by rule 30 and never evaluated
[LOW     ] rule 50: allow rule has zero hits; candidate for removal
Lateral path users -> scada: users -> servers -> scada
```

Exit code 1 on any critical finding, so it can gate firewall change requests.

## Egress: proxy enforcement and data exfiltration paths

Internal zones should reach the internet only through the web proxy, where TLS inspection, URL filtering and DLP run. `--egress` reads an `egress` block in the policy (proxy zone, zones that must use it, approved direct exceptions) and flags:

| ID | Severity | Finding |
|---|---|---|
| EG-01 | critical | Unrestricted outbound (service `any`) to the internet |
| EG-02 | high | Direct web traffic (80/443) that bypasses the proxy and its DLP inspection |
| EG-03 | high | Outbound FTP, SSH/SFTP, SMB, RDP, Tor or VPN: exfiltration channels DLP cannot see |
| EG-04 | medium | Other direct outbound not in the approved exceptions (external DNS, SMTP) |
| EG-05 | medium | Proxy zone itself allowing more than web ports out |

```bash
python -m segaudit.cli --rules samples/rules_egress.json --policy samples/policy_egress.json --egress
```

```
[CRITICAL] rule 260: unrestricted outbound from lab to the internet (any service)
[HIGH    ] rule 220: users reaches the web directly on tcp/443, bypassing the proxy and its DLP inspection
[HIGH    ] rule 230: servers can send data out over SSH/SFTP (tcp/22), which the proxy and DLP cannot inspect
[MEDIUM  ] rule 250: direct outbound udp/53 from users is not an approved exception
[MEDIUM  ] rule 270: proxy zone allows tcp/25 out; restrict it to web ports
```

The approved path (users -> proxy -> internet on 443) and the approved NTP exception produce no findings.
