#!/usr/bin/env python3
"""Local restricted-input diagnostic replay. Share only verification_summary.json.

Diagnostic reconstruction only; NOT authenticated Phase-19 inference reproduction.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT_SHA256 = {
    "pcap": "5ca6b0bd8ba7abf09399adffb4bb86505c8dd228273316bbd53e030acfeb5c56",
    "csv": "b24bf115c226025a476e1d65efca23e8c43186932ea484881983f26dc9128d59",
}
SCRIPTS = (
    ("directionality", "DDoS_Directionality_Final_Evidence_Audit.py"),
    ("segmentation", "DDoS_Final_Flow_Segmentation_Audit.py"),
    ("reconciliation", "DDoS_PCAP_Time_Flow_Reconciliation.py"),
)

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def main():
    p = argparse.ArgumentParser(description="Verify and replay frozen PCAP diagnostics locally")
    p.add_argument("--pcap", type=Path, required=True)
    p.add_argument("--csv", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    report = {
        "protocol": "frozen-input local diagnostic replay v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "historical exploratory PCAP/CSV diagnostics; NOT original model inference parity",
        "inputs": {},
        "runs": [],
        "all_inputs_verified": False,
        "all_scripts_succeeded": False,
    }
    report_path = args.out / "verification_summary.json"
    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    for kind, path in (("pcap", args.pcap), ("csv", args.csv)):
        if not path.is_file():
            report["inputs"][kind] = {"exists": False, "hash_matched": False}
            save()
            print(f"Missing {kind} input. Summary saved: {report_path}", file=sys.stderr)
            return 2
        matched = digest(path).lower() == INPUT_SHA256[kind]
        report["inputs"][kind] = {"exists": True, "hash_matched": matched}
        if not matched:
            save()
            print(f"Frozen {kind} SHA-256 mismatch; refusing experiment replay.", file=sys.stderr)
            return 3
    report["all_inputs_verified"] = True
    save()

    for tag, scriptname in SCRIPTS:
        script = ROOT / "scripts" / "historical" / scriptname
        if not script.is_file():
            report["runs"].append({"analysis": tag, "success": False, "reason": "script_missing"})
            save()
            break
        work = args.out / tag
        work.mkdir(exist_ok=True)
        command = [sys.executable, str(script), "--pcap", str(args.pcap),
                   "--csv", str(args.csv), "--out", str(work)]
        started = time.monotonic()
        with (work / "private_console.log").open("w", encoding="utf-8") as log:
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
        entry = {
            "analysis": tag,
            "success": process.returncode == 0,
            "exit_code": process.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "output_names": sorted(p.name for p in work.iterdir() if p.is_file()
                                   and p.name != "private_console.log"),
        }
        report["runs"].append(entry)
        save()
        if process.returncode != 0:
            print(f"{tag} failed. Consult private log in {tag} folder locally.", file=sys.stderr)
            break

    report["all_scripts_succeeded"] = len(report["runs"]) == len(SCRIPTS) and all(
        x["success"] for x in report["runs"])
    save()
    print(json.dumps({"all_inputs_verified": report["all_inputs_verified"],
                      "all_scripts_succeeded": report["all_scripts_succeeded"],
                      "analyses": [{"name": x["analysis"], "success": x["success"]}
                                   for x in report["runs"]]}, indent=2))
    print("Share ONLY verification_summary.json after inspecting it.")
    print("All other diagnostic outputs and private_console.log remain LOCAL and restricted.")
    return 0 if report["all_scripts_succeeded"] else 4

if __name__ == "__main__":
    raise SystemExit(main())
