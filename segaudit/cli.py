import argparse
import json
import sys

from .core import findings, lateral_paths

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit firewall rules against a segmentation policy.")
    ap.add_argument("--rules", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--path", nargs=2, metavar=("FROM", "TO"), action="append", default=[],
                    help="Check for a lateral path between two zones (repeatable)")
    a = ap.parse_args(argv)
    rules, policy = json.load(open(a.rules)), json.load(open(a.policy))
    res = sorted(findings(rules, policy), key=lambda f: SEV[f[1]])
    for rid, sev, msg in res:
        print(f"[{sev.upper():8}] rule {rid}: {msg}")
    for frm, to in a.path or [tuple(x) for x in policy.get("deny_always", [])]:
        p = lateral_paths(rules, frm, to)
        print(f"Lateral path {frm} -> {to}: " + (" -> ".join(p) if p else "none"))
    return 1 if any(s == "critical" for _, s, _ in res) else 0


if __name__ == "__main__":
    sys.exit(main())
