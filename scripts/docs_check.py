#!/usr/bin/env python3
"""Check generated artifacts, including untracked files in an initial checkout."""
from pathlib import Path
import hashlib
import subprocess

root = Path(__file__).resolve().parents[1]

def snapshot():
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ("docs", "examples")
            for p in (root / folder).rglob("*") if p.is_file()}

before = snapshot()
subprocess.run(["make", "generate"], cwd=root, check=True)
after = snapshot()
changed = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
if changed:
    raise SystemExit("Generated documentation differs: " + ", ".join(changed))
print("Generated docs and examples are consistent.")
