# Module 1 test suite

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests/test_module1.py      # run from the repository root
```

53 tests covering the ATT&CK lookup, scoring factors, end-to-end scoring, the ML fallback, the safety
guards, the Module 4 client and the capture helpers. Feeds and Module 4 are stubbed, so no network access
or API key is needed. Expected result: 53 passed. The suite also measures local decision time over 200
runs (reference values in `results/timings.json`, measured on 2 vCPU / 7 GB RAM / Python 3.11).

Not yet covered: the domain guard and the sticky manual-unblock override added in the final version.
