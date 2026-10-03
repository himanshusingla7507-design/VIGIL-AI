# VIGIL validation report

These synthetic examples do not represent real-world phishing prevalence and are not a substitute for dataset-level evaluation. Bare homepages of popular domains can still be misclassified by a URL-only model.

Passed: 6/13

| URL | Label | Probability | Risk | Expected | Pass |
|---|---:|---:|---:|---|---|
| https://google.com | SUSPICIOUS | 0.174197 | 8 | SAFE | False |
| https://github.com | SUSPICIOUS | 0.164589 | 6 | SAFE | False |
| https://microsoft.com | SUSPICIOUS | 0.165807 | 6 | SAFE | False |
| https://apple.com | SUSPICIOUS | 0.163865 | 6 | SAFE | False |
| https://amazon.com | SUSPICIOUS | 0.170500 | 7 | SAFE | False |
| https://python.org | SUSPICIOUS | 0.180289 | 9 | SAFE | False |
| https://cloudflare.com | SUSPICIOUS | 0.156086 | 4 | SAFE | False |
| https://fast.com/ | SAFE | 0.060029 | 0 | SAFE | True |
| https://paypal-login.example.com/verify-account | PHISHING | 0.997742 | 100 | PHISHING | True |
| http://secure-bank-login.example.com/update-account | PHISHING | 0.997742 | 100 | PHISHING | True |
| http://microsoft-security.example.com/login | PHISHING | 0.997715 | 100 | PHISHING | True |
| http://free-iphone-winner.example.com/claim | PHISHING | 0.997750 | 100 | PHISHING | True |
| http://account-verify.example.com/signin/password | PHISHING | 0.997742 | 100 | PHISHING | True |
