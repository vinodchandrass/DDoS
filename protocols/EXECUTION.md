# Reproducibility execution

## Public aggregate-count consistency
```bash
python scripts/validate_aggregates.py
```
This checks arithmetical consistency of deposited aggregates. It is not an independent replay.

## Historical PCAP/CSV diagnostics
Three historical read-only Python analyses exist in the research package:
- DDoS_Directionality_Final_Evidence_Audit.py
- DDoS_Final_Flow_Segmentation_Audit.py
- DDoS_PCAP_Time_Flow_Reconciliation.py

Those original scripts have not yet been uploaded pending file-level verification and transfer. Do not assume executable end-to-end reproduction from the current repository.

Historical inputs require authorized access to the original CSV and PCAP and exact SHA-256 checks. Running diagnostics can produce row-level outputs; **do not commit output folders**.

No original authenticated SOM–RF inference implementation, feature-extraction parity implementation, or Java inference baseline is provided.
