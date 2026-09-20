# Contributing to lanradar

Thanks for your interest! lanradar is deliberately small: **one file, zero
required dependencies**, Python 3.9+.

## The rules

1. `lanradar.py` stays a single, dependency-free file. No frameworks; `rich`
   stays optional.
2. If you add a code path, add an offline test — tests must never touch the
   network.
3. New engines must degrade gracefully: a missing binary or permission
   problem reports an empty result, it never crashes the sweep.
4. Keep the CLI backward compatible; document new flags in the README and
   `--help`.
5. The responsible-use notice in the README and `--help` is non-negotiable.

## Local development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # offline unit tests
lanradar 192.168.1.0/24   # smoke test on your own LAN
```

## Pull requests

* Small, focused PRs are easiest to review.
* Show real output in the PR description (table or `--json`).
* Pick an issue from the roadmap first if one fits.

Thanks! 🙏
