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

Live integration tests require an isolated lab, exact payload preview, rollback plan, and explicit approval. They must not run as part of the default unit-test suite.
