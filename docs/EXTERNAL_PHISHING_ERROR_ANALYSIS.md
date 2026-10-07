# External Phishing Error Analysis

Freshly measured, read-only evaluation of the untouched Phishing.Database phishing-only holdout against the current production model.

## Overall results

| Metric | Value |
|---|---:|
| Total samples | 154,931 |
| Detected phishing | 141,359 |
| Missed phishing | 13,572 |
| Recall | 0.9124 |
| False-negative rate | 0.0876 |
| Production phishing threshold | 0.696158 |

## Probability distribution

| Statistic | Probability |
|---|---:|
| min | 0.051636 |
| p01 | 0.143644 |
| p05 | 0.273446 |
| p25 | 0.997590 |
| median | 0.997812 |
| p75 | 0.997812 |
| p95 | 0.997918 |
| p99 | 0.998023 |
| max | 0.998822 |

## Top failure cohorts

| Dimension | Cohort | Samples | Missed | Miss rate |
|---|---|---:|---:|---:|
| pathless | yes | 39,359 | 13,572 | 0.3448 |
| url_length | <=60 | 84,778 | 13,572 | 0.1601 |
| suspicious_tld | no | 145,826 | 13,572 | 0.0931 |
| encoded_characters | no | 151,223 | 13,572 | 0.0897 |
| ip_hostname | no | 153,157 | 13,572 | 0.0886 |
| path_length | 0 | 37,138 | 13,565 | 0.3653 |
| url_structure | host-only | 37,138 | 13,565 | 0.3653 |
| query_parameters | 0 | 125,663 | 13,565 | 0.1079 |
| suspicious_tokens | no | 130,374 | 13,555 | 0.1040 |
| punycode_idn | no | 154,754 | 13,540 | 0.0875 |
| random_looking_tokens | no | 102,158 | 13,402 | 0.1312 |
| hostname_length | <=30 | 118,709 | 13,312 | 0.1121 |
| digit_count | 0 | 52,646 | 12,586 | 0.2391 |
| scheme | https | 118,540 | 10,733 | 0.0905 |
| hyphen_count | 0 | 75,570 | 10,433 | 0.1381 |

## Answers

1. **Detected well:** results are strongest for phishing URLs with highly distinctive lexical/structural signals such as long paths, suspicious tokens/TLDs, encoded characters, IP hosts, or strongly random-looking components.
2. **Missed:** the remaining false negatives are dominated by URLs whose lexical structure overlaps benign traffic—especially short or pathless URLs, ordinary-looking hostnames, low-entropy URLs, and URLs without suspicious-token/TLD/IP indicators.
3. **Top three feature gaps:** (a) weak semantic/reputation awareness for ordinary-looking domains, (b) limited campaign/brand-context signals beyond URL tokens, and (c) insufficient temporal/domain-age or infrastructure context. These are gaps in the URL-only design, not claims that a missing feature was tested here.
4. **Most promising single improvement:** add a leakage-safe, time-aware domain/infrastructure reputation feature available identically at training and inference, evaluated with strict unseen-domain and temporal splits.
5. **Next experiment:** run a time-split, domain-disjoint ablation comparing the current extractor against one carefully sourced reputation/domain-age feature and campaign-aware lexical features, with FPR and calibration as hard gates.

The holdout was not used for training, threshold selection, or model modification.
