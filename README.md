# SOHOWALL-CTI — Module 1: Cyber Threat Intelligence Scoring and Guarded Automated Enforcement

Module 1 of **SOHOWALL — A Multi-Layered Intelligent Firewall Architecture for SOHO Networks**
(SLIIT IT4010 Research Project 2026, group R26-CS-017).
Author: R.A.S. Udana (IT22233912). Supervisor: Mr. Amila Senarathne. Co-supervisor: Prof. Harinda Fernando.

Module 1 watches which destinations devices on a small network contact, scores each destination
with free public threat intelligence, and asks the SOHOWALL firewall module (Module 4) to block it
when the evidence is strong enough. It also streams traffic features to the anomaly detector (Module 2).

## How it works

```
capture (DNS / TLS SNI / TCP flags, or /api/ingest)
   -> recorder (single write path, background queues)
   -> scorer:  cache? -> URLhaus + ThreatFox + Feodo Tracker
               listed   : S = C x K x F   (ATT&CK severity x corroboration x freshness)
               unlisted : 7-model ML ensemble on host-name features
   -> decision: ENFORCE if S >= 0.6
   -> manager:  safety guards -> Module 4 external API (iptables / hosts sinkhole, audited)
```

* **Severity (C)** — derived offline from MITRE ATT&CK Enterprise 19.1 by counting the distinct threat
  groups that use each category's techniques (`tools/derive_severity.py`, audit trail in
  `docs/severity_derivation.md`, output in `config/severity_weights.json`).
* **Corroboration (K)** — 0.6 for one feed source, 0.8 for two.
* **Freshness (F)** — 1.0 (<7 days), 0.7 (<30), 0.5 (<90), 0.1 after; 0.5 if no date.
* **ML fallback** — Decision Tree, Random Forest, Extra Trees, Gradient Boosting, XGBoost, CatBoost and
  LightGBM, equal-weight average, 17 lexical host-name features (`app/cti/m1_model.py`).
* **Guards** — never blocks loopback, link-local, multicast, private (RFC 1918) or safelisted IPs, the
  abuse.ch feed domains, the Module 2 / Module 4 hosts, or safelisted domains. A manual unblock is sticky:
  the indicator is not auto-blocked again.

## Repository layout

| Path | Contents |
|---|---|
| `app/capture/` | Scapy sniffer, TLS ClientHello SNI parser, direction classifier, recorder |
| `app/cti/` | feed clients, ATT&CK tag mapping, scorer, ML predictor |
| `app/enforcement/` | guard manager and non-raising Module 4 client |
| `app/anomaly/` | live feature extractor and client for the Module 2 anomaly server |
| `app/routes/`, `app/templates/`, `app/static/` | dashboard pages and JSON API |
| `app/models/models/` | trained ML ensemble (leak-free, 17 features) |
| `config/` | category-to-technique map, malware-family synonyms, derived severity weights |
| `tools/derive_severity.py` | offline ATT&CK severity derivation |
| `training/retrain_m1.py` | training and evaluation script for the ML fallback |
| `tests/test_module1.py` | 53 automated tests (feeds and Module 4 stubbed) |
| `results/` | training report, sanity check, timing measurements and charts used in the thesis |
| `docs/severity_derivation.md` | reviewer-facing explanation of the severity weights |

## Quick start (Ubuntu, Python 3.11)

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then set ABUSECH_API_KEY, INGEST_TOKEN and the Module 4 token
python run.py                 # dashboard on http://localhost:8000
```

`CAPTURE_MODE=sniffer` needs root (`sudo -E .venv/bin/python run.py`). `ingest` mode accepts events
on `POST /api/ingest` with an `X-Ingest-Token` header.

**Enforcement is on by default** (`ENFORCEMENT_ENABLED=1`): every ENFORCE decision is sent to Module 4.
Set `ENFORCEMENT_ENABLED=0` to observe and score only. Module 4 must be running with a matching
`EXTERNAL_API_TOKEN` (default `http://localhost:5000`); Module 2 is optional (`http://localhost:5100`,
`ANOMALY_LIVE_SCORING_ENABLED=1` to stream features).

> The ML fallback scores raw IP addresses high (IP form is a strong feature and the training data has
> few benign raw IPs). Use `BLOCK_SAFELIST` for resolvers and other critical IPs, and treat IP blocks
> without feed evidence with care.

## Reproducing the thesis results

| Thesis item | Command |
|---|---|
| Tables 5.3 and 6.3 (53 tests, decision time) | `pip install -r requirements-dev.txt && python -m pytest -q tests/test_module1.py` |
| Table 6.1, Figure 6.1 (severity weights) | see `data/mitre/README.md`, then `python tools/derive_severity.py data/mitre/enterprise-attack-19.1.json 19.1` |
| Tables 3.1, 6.2, Figures 6.2–6.4 (ML fallback) | see `training/README.md` |

Reference outputs are in `results/` (`training_report.json`, `sanity_check.json`, `timings.json`, `charts/`).

## Related modules

Module 2 (anomaly detection, Dilshara N.P.G.R.), Module 3 (DLP, Pathiranage M.D.) and Module 4
(natural-language firewall, Dulanjana E.J.A.T.) are developed separately. Module 1 talks to Module 4 through
`POST /api/external/block`, `POST /api/external/unblock` and `GET /api/external/status`.

## Data and acknowledgements

Threat intelligence: [URLhaus](https://urlhaus.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/) and
[Feodo Tracker](https://feodotracker.abuse.ch/) by abuse.ch (free API key required).
ATT&CK: [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data), © The MITRE Corporation.
Training data: [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (Kaggle).
