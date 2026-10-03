# Historical audit (superseded by the current run below)

The counts below are from an earlier audit and are stale. Current audited counts are in [ml-evaluation.md](ml-evaluation.md) and [dataset_audit_report.json](../dataset_audit_report.json).

The command `python -c "import pandas as pd; ..."` reported shape `(235370, 2)` and columns `url`, `label`. The label distribution was 134,850 rows of `0` and 100,520 rows of `1`; sample rows showed ordinary domains with label `0`, while the dataset’s phishing class is represented by `1` in the training code.

The training clean pass reported zero removed missing URLs, missing labels, invalid labels, exact duplicate URLs, and conflicting normalized labels. The raw CSV is unchanged. Cleaning is deterministic in `train_model.py` and produces the in-memory cleaned frame used for training; a separate cleaned CSV artifact is not currently emitted.

The dataset audit did not use network lookups or a live suffix-list service. Registered-domain grouping uses the extractor’s conservative last-two-label fallback, which is a limitation for multi-label public suffixes such as `co.uk`.

The new extractor uses only URL-string features, canonicalizes lowercase hosts, strips `www.` and a root slash for analysis, and computes the same function during training and inference.
