# Contributing to LedgerLens

Thank you for considering contributing to LedgerLens! We welcome contributions from the community.

## How to Contribute

1. **Report Bugs**: Open an issue describing the bug, steps to reproduce, and expected behavior.
2. **Suggest Features**: Open an issue explaining the proposed feature and why it would be useful.
3. **Submit Pull Requests**:
   - Fork the repository.
   - Create a feature branch: `git checkout -b feature/my-feature`
   - Write unit tests for your changes.
   - Ensure all tests pass: `PYTHONPATH=. python3 tests/run_tests.py`
   - Submit a Pull Request targeting `main`.

## Development Setup

```bash
git clone https://github.com/zoecyber001/LedgerLens.git
cd LedgerLens
pip install -e .
```

## Code Style

- Follow PEP 8 guidelines.
- Use explicit type hints.
- Keep functions modular and focused.
- Ensure all tests pass before submitting your PR.
