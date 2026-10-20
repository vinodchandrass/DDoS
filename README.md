# DDoS–SDN evidence audit — reproducibility materials

Companion **reproducibility-only** repository for research on internal versus external SDN–IoT DDoS detection, protocol/date confounding, PCAP/CSV alignment, and selective inference. Manuscript, cover letters, and publication presentation figures are intentionally excluded.

**Status:** Partial, evidence-bounded reproducibility. **Not** complete inference-pipeline replication.

## Available materials
- `scripts/historical/`: three original diagnostic reconstructions, modified only to require portable `--pcap`, `--csv`, and `--out` arguments
- `scripts/validate_aggregates.py`, `scripts/check_input_hashes.py`, `scripts/inspect_dataset_schema.py`: consistency, identity, and schema verification utilities
- `results/published_aggregate_metrics.json`: previously reported aggregate measurements, **not** generated from a public run
- `protocols/EXECUTION.md`: local execution instructions and privacy precautions
- `protocols/INPUT_MANIFEST.md`: frozen SHA-256 input fingerprints
- `tests/` and `.github/workflows/`: arithmetic consistency tests and CI definition
- `docs/`: data-access and inference limitations

## Reported aggregate checkpoints
Internal validation: n=63,254 (TP=9,683; FN=586; FP=4,702; TN=48,283). External TCP-SYN diagnostic: n=6,233 (TP=1; FN=3,553; FP=18; TN=2,661). PCAP segmentation: short-duration matched 3,272/3,272; long-duration matched 0/281.

These metrics were previously recorded and are not independently recreated by this repository.

## Reproducibility limits
The original Phase 19 SOM–RF inference source was not authenticated, its inference parity remains unresolved, and independent feature-extractor equivalence is unverified. The historical scripts are diagnostic **reconstructions**, not recovered exporter or model inference source. No Java experimental implementation is claimed.

Raw datasets, PCAPs, row-level records, trained model and restricted internal evidence are excluded. Review rights before obtaining or redistributing third-party datasets. Generated diagnostic outputs can expose IP addresses and flow-level information and must **not** be committed.

See [execution instructions](protocols/EXECUTION.md), [data restrictions](docs/DATA_ACCESS.md), and [audit limitations](docs/REPRODUCIBILITY.md).

No software/data redistribution license is granted pending rights review.
