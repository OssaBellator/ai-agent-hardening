# Contributing

Contributions that improve the static scanner, tests, documentation, or safe GitHub Action integration are welcome.

## Design constraints

Changes to the scanner should preserve these boundaries:

- do not execute code from the target repository;
- do not install target dependencies;
- do not print suspected credential or private-key values;
- treat findings as review signals, not proof of compromise or safety;
- keep default GitHub Action permissions read-only;
- add regression tests for detector or parser changes.

## Validation

Run:

```bash
python -m unittest -v test_agent_hardening_check.py
python agent_hardening_check.py . --format markdown
```

The repository scan should not flag the scanner's own rule definitions.

## Pull requests

Keep changes scoped. Explain the behavior change, validation performed, and any new false-positive/false-negative trade-offs.
