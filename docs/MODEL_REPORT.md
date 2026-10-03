# Model report
# Model report

> Historical results from an earlier artifact. The active model, fresh split metrics, thresholds, calibration, and external-validation blockers are in [ml-evaluation.md](ml-evaluation.md). Do not use the numeric results below as current metrics.

> Historical results from an earlier artifact. The active model, fresh split metrics, thresholds, calibration, and external-validation blockers are in [ml-evaluation.md](ml-evaluation.md). Do not use the numeric results below as current metrics.

Training used 235,370 rows, 35 URL-only features, seed 42, and sigmoid calibration. Candidate validation PR-AUC/F1 were: logistic regression 0.9896/0.9606, random forest 0.9909/0.9706, and histogram gradient boosting 0.9922/0.9724. The selected base estimator was histogram gradient boosting, wrapped in `CalibratedClassifierCV`.

The recorded random split metrics are accuracy 0.976569, precision 0.988031, recall 0.956725, F1 0.972127, ROC-AUC 0.991580, PR-AUC 0.992550, FPR 0.008639, FNR 0.043275, Brier 0.019588, confusion matrix `[[26737,233],[870,19234]]`.

The recorded domain-aware holdout metrics are accuracy 0.981088, precision 0.983188, recall 0.964564, F1 0.973787, ROC-AUC 0.989089, PR-AUC 0.989369, FPR 0.009447, FNR 0.035436, Brier 0.017598, confusion matrix `[[26842,256],[550,14971]]`.

These are materially lower than the reported 99.69% random-split baseline, which supports the concern that the baseline benefited from dataset shortcuts. The current threshold metadata is `0.65` suspicious and `0.70` phishing, inherited from the run’s validation search; the training script still needs a stricter untouched final threshold-selection split before production use.

The active metadata threshold keys are `safe: 0.45` and `phishing: 0.85`; the service exposes these as `suspicious: 0.45` and `phishing: 0.85`. No external dataset was evaluated. The metrics are dataset-dependent, the class balance is artificial, and URL-only analysis cannot see page content or live threat intelligence.
