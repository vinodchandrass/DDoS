#!/usr/bin/env python3
"""Read-only schema/count audit of authorized CSV; emits aggregate summary only."""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    p.add_argument("csv",type=Path)
    p.add_argument("--label-column",default="Label")
    p.add_argument("--out",type=Path,help="Optional JSON output; no raw records included")
    a=p.parse_args()
    classes=Counter()
    with a.csv.open(newline="",encoding="utf-8-sig") as stream:
        reader=csv.DictReader(stream)
        cols=reader.fieldnames or []
        if a.label_column not in cols:
            raise SystemExit(f"Required column {a.label_column!r} missing")
        n=0
        for row in reader:
            n+=1
            classes[str(row.get(a.label_column,""))]+=1
    result={"rows":n,"column_count":len(cols),
            "columns":cols,"class_counts":dict(sorted(classes.items())),
            "scope":"aggregate schema audit, not feature extraction or inference replication"}
    message=json.dumps(result,indent=2)
    print(message)
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(message+"\n",encoding="utf-8")

if __name__=="__main__":
    main()
