# Contributing

1. Create a branch from the current main branch.
2. Do not add secrets, customer data, real IP addresses, or production readbacks.
3. Add or update tests for every behavior change.
4. Run:

```bash
PYTHONPATH=src python3 -m unittest discover -v
PYTHONPATH=src python3 -m compileall -q src tests
PYTHONPATH=src python3 -m edgeconnect_automation --help
```

5. Update `CHANGELOG.md` and operator documentation for user-visible changes.
6. Require review for API payload, safety-gate, retry, rollback, dependency, or verification changes.
7. Never add automatic confirmation bypasses or silent field dropping.

`tests/test_golden.py` compares what representative commands print and write with the files in `tests/golden/`. When you change CLI output on purpose, regenerate them with `EDGECONNECT_UPDATE_GOLDEN=1 PYTHONPATH=src python3 -m unittest tests.test_golden` and review the diff.

GitHub Actions runs the first three commands on Python 3.9 and 3.13, on Linux and macOS, for every pull request (`.github/workflows/test.yml`).

Live integration tests require an isolated lab, exact payload preview, rollback plan, and explicit approval. They must not run as part of the default unit-test suite.
