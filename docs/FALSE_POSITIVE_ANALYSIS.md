# `fast.com` false-positive analysis

An earlier VIGIL pipeline over-classified some legitimate URLs, including `fast.com`, because URL-shape differences were amplified by a trusted-domain shortcut and arbitrary score logic. That made the result dependent on the exact spelling of a URL variant rather than on a stable inference path.

The remediation was architectural: canonicalize URLs consistently, centralize prediction in `service.py`, remove arbitrary score boosts, remove trusted-domain bypass behavior, and preserve evidence as an explanation rather than as a second score. No `fast.com` exception was added.

The current checked-in synthetic validation report records `https://fast.com/` as `SAFE`, with probability `0.060029` and risk `0`. This verifies the documented regression case for that input in the local bundle; it does not prove that every variant or future model will behave identically.

This case is useful because it demonstrates a train/serve and policy debugging problem, not just a headline accuracy number. The full model limitations remain in [the evaluation report](ml-evaluation.md).

## Amazon shopping routes

URL-structure models can mistake ordinary product and cart paths for phishing. The current runtime therefore recognizes a narrow set of shopping routes on the exact `amazon.com` and `www.amazon.com` hosts. It preserves the calibrated model score for diagnostics while preventing URL-shape-only blocks on those routes. It does not trust Amazon-named lookalikes, arbitrary subdomains, malformed product IDs, or redirect-style URLs. This route policy reduces a known false-positive mode; it is not a claim that the Amazon model score itself is accurate or that every Amazon page is safe.
