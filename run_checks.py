#!/usr/bin/env python3
"""Cross-platform one-command validation entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(command: list[str]) -> None:
    printable = " ".join(f'"{part}"' if " " in part else part for part in command)
    print(f"\n$ {printable}", flush=True)
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(command, cwd=ROOT, env=env)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> int:
    python = sys.executable
    run([python, "-m", "unittest", "discover", "-s", "tests", "-v"])
    run([python, str(ROOT / "scale_check.py")])
    run([python, str(ROOT / "run_demo.py")])
    run([
        python,
        str(ROOT / "verify_evidence.py"),
        str(ROOT / "artifacts" / "demo-evidence" / "evidence.json"),
        "--keyring",
        str(ROOT / "artifacts" / "demo-evidence" / "trusted-keyring.json"),
    ])
    print("\nALL_OFFLINE_AUDIT_CHECKS_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
