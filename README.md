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
