# `fast.com` false-positive analysis

An earlier VIGIL pipeline over-classified some legitimate URLs, including `fast.com`, because URL-shape differences were amplified by a trusted-domain shortcut and arbitrary score logic. That made the result dependent on the exact spelling of a URL variant rather than on a stable inference path.

The remediation was architectural: canonicalize URLs consistently, centralize prediction in `service.py`, remove arbitrary score boosts, remove trusted-domain bypass behavior, and preserve evidence as an explanation rather than as a second score. No `fast.com` exception was added.

The current checked-in synthetic validation report records `https://fast.com/` as `SAFE`, with probability `0.060029` and risk `0`. This verifies the documented regression case for that input in the local bundle; it does not prove that every variant or future model will behave identically.

This case is useful because it demonstrates a train/serve and policy debugging problem, not just a headline accuracy number. The full model limitations remain in [the evaluation report](ml-evaluation.md).
