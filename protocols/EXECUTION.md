# Reproducibility execution

## Public aggregate consistency
```bash
python scripts/validate_aggregates.py
python -m unittest discover -s tests -v
```
These tests establish arithmetic consistency only, **not independent data-level replication**.

## Historical PCAP/CSV diagnostic scripts
First obtain the authorized original PCAP and CSV. Independently verify frozen source hashes documented in [INPUT_MANIFEST.md](INPUT_MANIFEST.md).

```bash
python scripts/check_input_hashes.py PATH_TO_PCAP --expected 5ca6b0bd8ba7abf09399adffb4bb86505c8dd228273316bbd53e030acfeb5c56
python scripts/check_input_hashes.py PATH_TO_CSV --expected b24bf115c226025a476e1d65efca23e8c43186932ea484881983f26dc9128d59
pip install -r requirements.txt
python scripts/historical/DDoS_Directionality_Final_Evidence_Audit.py --pcap PATH_TO_PCAP --csv PATH_TO_CSV --out outputs/directionality
python scripts/historical/DDoS_Final_Flow_Segmentation_Audit.py --pcap PATH_TO_PCAP --csv PATH_TO_CSV --out outputs/segmentation
python scripts/historical/DDoS_PCAP_Time_Flow_Reconciliation.py --pcap PATH_TO_PCAP --csv PATH_TO_CSV --out outputs/reconciliation
```

**Important:** The first two historical scripts enforce the frozen input hashes; the reconciliation script does *not*, so check the inputs yourself before running it. Script defaults were replaced by required CLI arguments for portability, without intentionally altering analytical logic.

Output files may contain row-level network identifiers, timestamps, flow tuples and other sensitive traffic evidence. Keep `outputs/` private; do not upload generated artifacts or command-line traces that expose local paths.

No original authenticated SOM–RF inference implementation, feature-extraction parity implementation, or Java inference baseline is supplied. Historical outputs have **not** been rerun in this public repository.
