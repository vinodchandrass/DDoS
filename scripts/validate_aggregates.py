#!/usr/bin/env python3
"""Audit the frozen published confusion-count summaries; no raw dataset needed."""
import json
from pathlib import Path

def metrics(x):
    tp, fn, fp, tn = (int(x[k]) for k in ("TP", "FN", "FP", "TN"))
    n = tp + fn + fp + tn
    return {"n": n, "recall": tp/(tp+fn), "precision": tp/(tp+fp),
            "f1": 2*tp/(2*tp+fp+fn), "false_positive_rate": fp/(fp+tn)}

def main():
    root = Path(__file__).resolve().parents[1]
    x = json.loads((root/"results"/"published_aggregate_metrics.json").read_text(encoding="utf-8"))
    for name in ("internal_validation", "external_TCP_SYN"):
        reported = x[name]
        got = metrics(reported)
        assert got["n"] == reported["n"], f"{name}: confusion counts do not sum to n"
        print(name, json.dumps(got, sort_keys=True))
    s = x["segmentation_diagnostic"]
    assert 0 <= s["short_flow_matched"] <= s["short_flow_total"]
    assert 0 <= s["long_flow_matched"] <= s["long_flow_total"]
    print("PASS: aggregate consistency (not independent raw-data replication)")

if __name__ == "__main__":
    main()
