"""
UniShield - Verify passive (read-only) operation

Static scan of src/unishield for networking, packet-sending, capture,
process and crypto capabilities, plus a runtime tripwire around socket and
scapy send/receive functions while every input format and the API run.
Writes reports/passive_mode_verification.{json,md}; exits 1 on any finding.

Usage:
    python scripts/verify_passive_mode.py [--static-only]
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from unishield.evaluation.passive import render_markdown, verify


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args()

    report = verify(run_runtime=not args.static_only)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "passive_mode_verification.json").write_text(
        json.dumps(dict(report.to_dict(), generated_at=generated), indent=2), encoding="utf-8")
    (args.out / "passive_mode_verification.md").write_text(render_markdown(report, generated), encoding="utf-8")

    print(f"Static scan: {report.files_scanned} modules, {len(report.static_findings)} findings")
    for f in report.static_findings:
        print(f"  {f.file}:{f.line} {f.kind} {f.name}")
    print(f"Runtime: {len(report.runtime_exercised)} paths exercised, "
          f"{len(report.runtime_attempts)} network attempts")
    for a in report.runtime_attempts:
        print(f"  {a}")
    print("PASSED" if report.passed else "FAILED")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
