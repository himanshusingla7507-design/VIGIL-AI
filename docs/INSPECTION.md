# Repository inspection record

This file records the historical engineering inspection that led to the current shared inference service. It is context, not a source of current metrics; use [ml-evaluation.md](ml-evaluation.md) for the latest evaluation.

The inspection identified inconsistent URL-shape handling, trusted-domain bypass behavior, heuristic score additions, test-split threshold selection, and duplicated extension logic. The current implementation addresses those concerns with canonicalization, centralized inference in `service.py`, calibrated model metadata, structured evidence, restricted CORS, and an extension client that delegates to `/scan`.

The repository now includes a React/Vite frontend, persisted history endpoints, frontend tests, and a production build. The local dataset remains provenance-limited and the model remains URL-only; those limitations are documented rather than hidden.
