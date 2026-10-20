# Frozen input verification

Historical PCAP and CSV analysis requires the following frozen hashes:

- External TCP-SYN PCAP SHA-256: `5ca6b0bd8ba7abf09399adffb4bb86505c8dd228273316bbd53e030acfeb5c56`
- Paired external TCP-SYN CSV SHA-256: `b24bf115c226025a476e1d65efca23e8c43186932ea484881983f26dc9128d59`

Use `python scripts/check_input_hashes.py PATH --expected HASH` to verify each original file. The repository does not include these inputs.

For authorized CSV datasets, run `python scripts/inspect_dataset_schema.py PATH --label-column Label` to inspect aggregate column and label counts.

These scripts verify input identity/schema only; they do not reconstruct the original feature extraction or SOM–RF inference.
