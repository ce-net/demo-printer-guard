#!/usr/bin/env python3
"""Compare two try-all reports byte for byte after removing timestamps ("at", "generated_at")."""
import json, sys

def strip(v):
    if isinstance(v, dict):
        return {k: strip(x) for k, x in v.items() if k not in ("at", "generated_at")}
    if isinstance(v, list):
        return [strip(x) for x in v]
    return v

a, b = (json.dumps(strip(json.load(open(p))), indent=2, sort_keys=True) for p in sys.argv[1:3])
if a != b:
    import difflib
    sys.stdout.writelines(difflib.unified_diff(a.splitlines(True), b.splitlines(True), sys.argv[1], sys.argv[2]))
    sys.exit(1)
print(f"{sys.argv[2]} matches {sys.argv[1]} (timestamps aside)")
