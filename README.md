# DDoS–SDN Evidence Audit

Research companion repository for **When Internal Detection Does Not Transfer: An Evidence Audit of Confounding, Feature Shift, and Selective Inference in SDN–IoT Traffic**.

**Release status: partial research archive; not end-to-end executable replication.**

The study examines confounding, cross-dataset detection failure, PCAP reconciliation, and flow directionality for a SOM–RF SDN–IoT detector.

## Reported aggregate evidence
- Internal validation: n=63,254; TP=9,683, FN=586, FP=4,702, TN=48,283.
- External TCP-SYN diagnostic: n=6,233; TP=1, FN=3,553, FP=18, TN=2,661.
- Short-flow segmentation matches: 3,272/3,272; longer-flow matches: 0/281.

These values are transcribed from previously reported audit checkpoints and have **not** been independently rerun from repository contents.

## Reproducibility limitations
The original Phase 19 model inference implementation has not been authenticated; original inference parity and external feature-extractor equivalence remain unverified. PCAP segmentation and directionality analyses are diagnostic and do **not** reproduce or authenticate the original exporter.

Restricted raw datasets, packet captures, row-level traffic, frozen model weights and internal evidence archive are not supplied. Obtain inputs from authorized sources and verify redistribution rights.

See [data access](docs/DATA_ACCESS.md) and [reproducibility statement](docs/REPRODUCIBILITY.md).

## Software availability
Three newly prepared, read-only reproducibility utilities are available: `scripts/validate_aggregates.py` (arithmetic checks of deposited counts), `scripts/check_input_hashes.py` (frozen input identity), and `scripts/inspect_dataset_schema.py` (aggregate schema/label-count checks). The historical PCAP directionality and segmentation scripts are **not yet committed** pending a further file-by-file release audit. No authenticated Java implementation was used for this DDoS–SDN study. See `protocols/EXECUTION.md` and `protocols/INPUT_MANIFEST.md`. Manuscript and publication graphics are excluded by the author's release policy.

## Licensing
No explicit software or data license is granted at this time, pending third-party rights review.

**Author:** Vinod Chandra S. S., Department of Computer Science, University of Kerala.
