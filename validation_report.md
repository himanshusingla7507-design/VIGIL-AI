# VIGIL validation report

These synthetic examples do not represent real-world phishing prevalence and are not a substitute for dataset-level evaluation. Bare homepages of popular domains can still be misclassified by a URL-only model.

Passed: 13/13

| URL | Label | Probability | Risk | Expected | Pass |
|---|---:|---:|---:|---|---|
| https://google.com | SAFE | 0.021837 | 0 | SAFE | True |
| https://github.com | SAFE | 0.013584 | 0 | SAFE | True |
| https://microsoft.com | SAFE | 0.011354 | 0 | SAFE | True |
| https://apple.com | SAFE | 0.010953 | 0 | SAFE | True |
| https://amazon.com | SAFE | 0.020521 | 0 | SAFE | True |
| https://python.org | SAFE | 0.028633 | 0 | SAFE | True |
| https://cloudflare.com | SAFE | 0.010780 | 0 | SAFE | True |
| https://fast.com/ | SAFE | 0.003954 | 0 | SAFE | True |
| https://paypal-login.example.com/verify-account | PHISHING | 0.998246 | 100 | PHISHING | True |
| http://secure-bank-login.example.com/update-account | PHISHING | 0.998445 | 100 | PHISHING | True |
| http://microsoft-security.example.com/login | PHISHING | 0.998445 | 100 | PHISHING | True |
| http://free-iphone-winner.example.com/claim | PHISHING | 0.998445 | 100 | PHISHING | True |
| http://account-verify.example.com/signin/password | PHISHING | 0.998445 | 100 | PHISHING | True |
