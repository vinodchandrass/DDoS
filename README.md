# DDoS–SDN evidence audit — reproducibility materials

Companion **reproducibility-only** repository for research on internal versus external SDN–IoT DDoS detection, protocol/date confounding, PCAP/CSV alignment, and selective inference. Manuscript, cover letters, and publication presentation figures are intentionally excluded.

**Status:** Partial, evidence-bounded reproducibility. **Not** complete inference-pipeline replication.

## Available materials
- `scripts/historical/`: three original diagnostic reconstructions, modified only to require portable `--pcap`, `--csv`, and `--out` arguments
- `scripts/validate_aggregates.py`, `scripts/check_input_hashes.py`, `scripts/inspect_dataset_schema.py`: consistency, identity, and schema verification utilities
- `results/published_aggregate_metrics.json`: previously reported aggregate confusion-count measurements
- `results/local_replay_verification_summary.json` and `results/numerical_concordance_checkpoint.json`: documented successful frozen-input diagnostic execution and aggregate numerical agreement (local workstation only)
- `scripts/run_frozen_diagnostics.py` and `scripts/extract_concordance.py`: local hash-gated diagnostic execution and sanitized aggregate extraction
- `protocols/EXECUTION.md`: local execution instructions and privacy precautions
- `protocols/INPUT_MANIFEST.md`: frozen SHA-256 input fingerprints
- `tests/` and `.github/workflows/`: arithmetic consistency tests and CI definition
- `docs/`: data-access and inference limitations

## Reported aggregate checkpoints
Internal validation: n=63,254 (TP=9,683; FN=586; FP=4,702; TN=48,283). External TCP-SYN diagnostic: n=6,233 (TP=1; FN=3,553; FP=18; TN=2,661). PCAP segmentation: short-duration matched 3,272/3,272; long-duration matched 0/281.

These metrics were previously recorded. Selected PCAP/CSV diagnostic counts were reproduced by a frozen-input rerun on the authorized research workstation; the public GitHub CI does not have restricted inputs and does not recreate those results.

## Reproducibility limits
The original Phase 19 SOM–RF inference source was not authenticated, its inference parity remains unresolved, and independent feature-extractor equivalence is unverified. The historical scripts are diagnostic **reconstructions**, not recovered exporter or model inference source. No Java experimental implementation is claimed.

Raw datasets, PCAPs, row-level records, trained model and restricted internal evidence are excluded. Review rights before obtaining or redistributing third-party datasets. Generated diagnostic outputs can expose IP addresses and flow-level information and must **not** be committed.

See [execution instructions](protocols/EXECUTION.md), [data restrictions](docs/DATA_ACCESS.md), and [audit limitations](docs/REPRODUCIBILITY.md).

No software/data redistribution license is granted pending rights review.

## Final diagnostic checkpoint (20 October 2026)

Using the original hash-matched PCAP/CSV, all three diagnostic scripts completed successfully. Each read 5,378,657 packets without a recorded packet-processing error. The reconciliation matched 3,553/3,554 attack tuples; the swapped-direction candidate matched 3,272/3,272 short flows, but 0/281 longer flows. These are hypothesis-specific diagnostic comparisons, **not** exporter authentication or independent inference reproduction.

The verification records report aggregate numerical concordance but do not contain raw traffic, packet traces or row-level evidence. GitHub Actions validates code structure, command-line availability and arithmetic checks without running restricted-data experiments.
