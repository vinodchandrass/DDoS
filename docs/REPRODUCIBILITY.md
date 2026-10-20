# Reproducibility boundaries and verification status

## Verified on authorized local workstation (20 October 2026)
The frozen PCAP and CSV matched their registered SHA-256 checksums. All three released exploratory diagnostic scripts completed with exit code zero. The numerical-concordance extraction reported 5,378,657 packets per analysis and no packet-processing errors; it also confirmed the 3,553/3,554 tuple reconciliation and short-versus-long swapped-direction joint matching (3,272/3,272 versus 0/281 under the specified candidate).

Evidence records:
- [Local execution summary](../results/local_replay_verification_summary.json)
- [Numerical concordance checkpoint](../results/numerical_concordance_checkpoint.json)
- [Execution protocol](../protocols/EXECUTION.md)

## Explicit limitations
- Historical scripts are exploratory PCAP/CSV reconstruction diagnostics, **not** the authenticated original flow exporter.
- The original Phase 19 SOM–RF inference source remains unauthenticated; inference parity is **unverified**.
- Feature-extractor equivalence for the external dataset is **unverified**.
- Packet tuple matching is not proof of a one-to-one correspondence between original exported flows and reconstructed segments.
- GitHub Actions performs only static, interface and aggregate arithmetic tests; it does not replay restricted network traffic or validate original model predictions.
- Raw datasets, packet captures, row-level diagnostics, frozen model weights and internal evidence files are restricted and not redistributed.
- No Java experimental implementation has been authenticated for this study.

Thus, the current release supports inspection of algorithms, input-integrity checks, local reruns by authorized holders of the frozen inputs, and aggregate numerical concordance. **It is not a complete independent end-to-end replication package.**
