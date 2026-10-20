#!/usr/bin/env python3
"""Generate a whitelist-only, aggregate numerical concordance report.

Reads private diagnostic JSON files locally and writes no paths, IPs, flow tuples,
timestamps, row-level results, or source hashes. Never upload raw JSON inputs.
"""
import argparse
import json
from pathlib import Path

def load(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)

def numeric(x):
    return isinstance(x,(int,float)) and not isinstance(x,bool)

def subset(obj, fields):
    return {k:obj[k] for k in fields if k in obj and numeric(obj[k])}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True,help="Private public_diagnostic_replay output directory")
    p.add_argument("--out",type=Path,required=True,help="Filename for sanitized aggregate JSON report")
    a=p.parse_args()
    inputs={
        "directionality":a.root/"directionality"/"directionality_evidence_summary.json",
        "segmentation":a.root/"segmentation"/"segmentation_summary.json",
        "reconciliation":a.root/"reconciliation"/"reconciliation_summary.json"
    }
    data={k:load(v) for k,v in inputs.items()}
    top_fields=("packets_read","relevant_packets","packet_processing_errors",
                "attack_csv_rows","matched_attack_tuples","excluded_rows",
                "candidate_count","tcp_attack_tuple_keys","tcp_attack_tuple_keys_present",
                "excluded_attack_rows","pcap_packets_read","pcap_packet_processing_errors",
                "csv_rows_labelled","attack_rows","attack_rows_with_tuple_in_pcap",
                "attack_rows_without_tuple_in_pcap","attack_unique_tuple_keys",
                "pcap_first_within_csv_minute_offset_0_true",
                "pcap_first_within_csv_minute_offset_5.5_true",
                "csv_fwd_count_le_pcap_total_true","csv_bwd_count_le_pcap_total_true")
    report={"scope":"aggregate-only numerical concordance; not SOM-RF inference replication",
            "results":{k:subset(obj,top_fields) for k,obj in data.items()},
            "directionality_candidates":[],
            "segmentation_candidates":[],
            "reconciliation_distributions":{}}
    allowed_dir=("rows","eligible_start","original_joint","swapped_joint",
                 "either_joint","total_duration_joint","duration_only",
                 "unique_swapped_joint","unique_original_joint")
    for row in data["directionality"].get("summary",[]):
        if not isinstance(row,dict):continue
        config=row.get("configuration");stratum=row.get("stratum")
        if config not in ("idle_0p1","idle_120","rst_terminated"):continue
        if stratum not in ("all","short_le_1s","long_gt_1s"):continue
        report["directionality_candidates"].append({"configuration":config,"stratum":stratum,**subset(row,allowed_dir)})
    seg_fields=("eligible_attack_rows","rows_with_start_minute_segment",
                "rows_with_packet_count_match","rows_with_duration_match_5pct_or_10us",
                "rows_with_joint_packet_duration_match")
    for row in data["segmentation"].get("candidate_results",[]):
        if not isinstance(row,dict):continue
        item=subset(row,("idle_timeout_s","active_timeout_s")+seg_fields)
        report["segmentation_candidates"].append(item)
    allowed_summaries=("pcap_forward_packets_all_summary","pcap_reverse_packets_all_summary",
       "pcap_tuple_span_seconds_summary","csv_duration_summary")
    for field in allowed_summaries:
        obj=data["reconciliation"].get(field)
        if isinstance(obj,dict):
            report["reconciliation_distributions"][field]=subset(obj,("n","min","median","max"))
    # This checks only an independently reported aggregate fact; avoid claiming
    # the other figures match without direct numerical comparison.
    recon=report["results"]["reconciliation"]
    expected={"attack_rows":3554,"attack_rows_with_tuple_in_pcap":3553,
              "attack_rows_without_tuple_in_pcap":1}
    report["reconciliation_expected_check"]={
        k:{"expected":v,"observed":recon.get(k),"match":recon.get(k)==v if k in recon else None}
        for k,v in expected.items()}
    report["reconciliation_expected_all_match"]=all(
        item["match"] is True for item in report["reconciliation_expected_check"].values())
    report["notes"]=[
        "All candidate rows reflect local diagnostic reconstruction hypotheses, not authenticated exporter behavior.",
        "A matching tuple count does not verify original SOM-RF inference or feature-extractor equivalence.",
        "Short/long duration claims require targeted comparison to the candidate-stratum aggregates.",
        "The report contains only explicitly whitelisted aggregate numeric values; inspect before sharing."
    ]
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2,allow_nan=False)+"\n",encoding="utf-8")
    print("Created sanitized numerical report. Review locally before sharing.")
    print("Concordance of previously reported reconciliation counts:",report["reconciliation_expected_all_match"])

if __name__=="__main__":
    main()
