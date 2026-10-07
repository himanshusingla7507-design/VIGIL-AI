# Final Promotion Gate

## DO NOT PROMOTE

The domain-only hostname character model is **not promoted**. The current `CalibratedHistGradientBoosting` production model remains active, and the four production artifacts were not overwritten.

The candidate improved the registered-domain-grouped test metrics:

| Metric | Current | Domain-only | Change |
|---|---:|---:|---:|
| PR-AUC | 0.99390 | 0.99671 | +0.00281 |
| ROC-AUC | 0.96606 | 0.98138 | +0.01532 |
| Phishing recall | 0.87694 | 0.93208 | +0.05515 |
| FNR | 0.12306 | 0.06792 | -0.05515 |
| FPR | 0.01031 | 0.00864 | -0.00167 |
| F1 | 0.93346 | 0.96403 | +0.03057 |
| Brier | 0.06438 | 0.03718 | -0.02720 |
| ECE | 0.05170 | 0.00792 | -0.04377 |

On the 154,931-row phishing-only Phishing.Database holdout, recall improved from `0.91240` to `0.96750` and FNR fell from `0.08760` to `0.03250`. FPR is undefined because every holdout row is phishing; this holdout was not used for fitting, feature selection, calibration, or threshold selection, and no overall accuracy claim is made.

The candidate also improved the reported hard-case phishing recall: pathless `0.6250 → 0.8867`, short `0.7901 → 0.9156`, no suspicious token `0.8549 → 0.9292`, no suspicious TLD `0.8682 → 0.9279`, no digits `0.7014 → 0.8844`, and ordinary-looking domains `0.8433 → 0.9244`.

The gate nevertheless fails. Candidate fast.com predictions were not persisted by the read-only experiment, so the explicit requirement that all fast.com canonical variants remain SAFE cannot be certified. The existing legitimate-reference summary also does not contain the complete candidate SAFE/SUSPICIOUS/PHISHING triage counts required by the gate. Finally, the candidate is approximately `9,682,206` bytes versus `1,100,240` bytes for production—`8.8×` larger—so model-size acceptability is not established even though measured single-row latency was lower (`4.07 ms` versus `29.45 ms`).

All executable regression suites passed: backend pytest `15/15`, frontend Vitest `3/3`, frontend TypeScript/Vite build, extension tests `8/8`, extension syntax checks, and API contract checks for `/scan`, `/health`, `/model-info`, and `/history`.

Because the promotion rule requires every gate to pass, the missing candidate regressions and unestablished size/safety acceptance are decisive. No domain-specific exception, trusted-domain bypass, or score boost was added. See the machine-readable evidence in [`reports/final_promotion_gate.json`](../reports/final_promotion_gate.json).
