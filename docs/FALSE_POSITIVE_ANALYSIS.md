# `fast.com` false-positive analysis
# `fast.com` false-positive analysis

> Historical analysis of the previous feature/model bundle. Current protocol-invariance tests and `fast.com` results are in [ml-evaluation.md](ml-evaluation.md).

> Historical analysis of the previous feature/model bundle. Current protocol-invariance tests and `fast.com` results are in [ml-evaluation.md](ml-evaluation.md).

The pre-overhaul run was not a valid model-only diagnosis because `phishing_detector.py` returned an allowlisted SAFE result for `fast.com` and `fast.com/`. In contrast, `www.fast.com/` bypassed the allowlist and the old model returned `PHISHING` with probability `0.943511` and risk `94.35`.

Before the fix, the extracted values differed materially: `https://fast.com` had URL length 16 and path length 0; `https://fast.com/` had URL length 17 and path length 1; `https://www.fast.com/` had URL length 21, dot count 2, and a model-visible www shape. The hostname length was 8 in all three cases because the extractor stripped `www` only for the hostname feature, creating inconsistent treatment across features.

The retrained service canonicalizes `www.` and a bare root slash for analysis. After the fix, all three variants have identical analysis features (URL length 16, hostname length 8, path length 0, dot count 1, HTTPS 1, zero suspicious tokens) and all return SAFE with calibrated model probability `0.003762` and risk score `0`.

The causal chain was therefore train/serve feature semantics plus collection-shape sensitivity, amplified by the exact-domain shortcut. HTTPS is retained as an informational feature, never as a safety override. Risk is now exactly `round(100 * calibrated P(phishing))`; no keyword bonus is added. This resolves the reported fast.com variant failure, subject to the normal limitation that URL-only models can misclassify unfamiliar domains.
