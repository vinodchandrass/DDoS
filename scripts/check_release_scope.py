#!/usr/bin/env python3
"""Read-only release-policy gate for DDoS–SDN reproducibility repository."""
from pathlib import Path
import subprocess
import sys

PROHIBITED_SUFFIXES={".pdf",".tex",".pcap",".pcapng",".joblib",".pkl",".pickle",".parquet",".xlsx",".xls",".docx",".pptx"}
PROHIBITED_PARTS={"manuscript","submission","cover_letter","raw_data","dataset_raw","trained_model","model_weights"}
ALLOWED_EXTENSIONS={".md",".txt",".json",".yml",".yaml",".py",".gitignore",".toml",".cfg",".ini",".csv"}
ROOT=Path(__file__).resolve().parents[1]

def tracked_paths():
    try:
        proc=subprocess.run(["git","ls-files","-z"],cwd=ROOT,check=True,capture_output=True)
        return [Path(p.decode("utf-8")) for p in proc.stdout.split(b"\0") if p]
    except (OSError,subprocess.CalledProcessError):
        return [p.relative_to(ROOT) for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]

def main():
    violations=[]
    paths=tracked_paths()
    for rel in paths:
        name=rel.name.lower()
        parts={p.lower() for p in rel.parts}
        if rel.suffix.lower() in PROHIBITED_SUFFIXES:
            violations.append(f"Restricted file type: {rel}")
        if parts & PROHIBITED_PARTS or any(s in name for s in ("manuscript","cover_letter")):
            violations.append(f"Restricted content path: {rel}")
        if rel.suffix and rel.suffix.lower() not in ALLOWED_EXTENSIONS:
            violations.append(f"Unreviewed extension: {rel}")
        if not (ROOT/rel).is_file():
            violations.append(f"Tracked file missing from checkout: {rel}")
    if violations:
        print("\n".join(violations),file=sys.stderr)
        return 1
    print(f"PASS: {len(paths)} tracked files meet structural reproducibility-only release rules")
    print("WARNING: Static path checks do not verify licensing, privacy, dataset provenance, or scientific reproduction")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
