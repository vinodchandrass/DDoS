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


## Combined frozen-input replay (recommended)

Run on the Windows workstation that already holds the restricted PCAP and CSV. Clone the public repository separately; **do not commit the resulting output directory**.

```powershell
cd D:\\DDoS
git clone https://github.com/vinodchandrass/DDoS.git Reproducibility_Public
cd Reproducibility_Public
python -m pip install -r requirements.txt
python scripts/run_frozen_diagnostics.py --pcap "D:\\DDoS\\data\\TCP-SYN attack 3_17-3_25.pcap" --csv "D:\\DDoS\\data\\TCP-SYNC DATASET.csv" --out "D:\\DDoS\\results\\public_diagnostic_replay"
```

The runner refuses execution unless both input SHA-256 values match the frozen evidence. It executes all three historical diagnostic analyses sequentially, stopping if a step fails. It creates a *minimal* report at:

`D:\\DDoS\\results\\public_diagnostic_replay\\verification_summary.json`

**The only file to share for this checkpoint is `verification_summary.json`, after reviewing it.** It records boolean input-hash matches and per-script success/output filenames, without embedding packet data, local absolute paths, source hashes, row-level records or private console output. All raw diagnostics and `private_console.log` remain on the workstation. Do not upload the complete output folder.

Passing this runner is a workflow check, **not** numerical comparison to every frozen result, authentication of the original exporter, or verification of original SOM–RF inference parity.


## Numerical concordance extraction (no need to rerun PCAP analyses)

When the three frozen-input analyses have already completed, generate a **whitelist-only aggregate report** from their existing private outputs:

```powershell
cd D:\\DDoS\\Reproducibility_Public
git pull --ff-only
python scripts/extract_concordance.py --root "D:\\DDoS\\results\\public_diagnostic_replay" --out "D:\\DDoS\\results\\public_diagnostic_replay\\concordance_aggregates_only.json"
```

Inspect `concordance_aggregates_only.json` locally, then share only this small summary privately for numerical comparison. Do not upload the underlying output JSON, row diagnostics, PCAP, CSV or logs to GitHub. This tool does not change any raw data or rerun packet processing. Its numeric checks are intentionally narrow; passing a count comparison does not establish model inference or full exporter parity.
