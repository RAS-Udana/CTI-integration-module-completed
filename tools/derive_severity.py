#!/usr/bin/env python3
"""
tools/derive_severity.py — derive severity weights from MITRE ATT&CK.

Runs OFFLINE, once per ATT&CK release. Never at scoring time.
The scoring module only ever reads the committed
config/severity_weights.json output of this script.

Usage:
    python tools/derive_severity.py data/mitre/enterprise-attack-19.1.json 19.1
"""
import json
import hashlib
import datetime
import logging
import sys
import os
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.category_technique_map import CATEGORY_TECHNIQUE_MAP  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("derive_severity")

S_MIN = 0.10


def attack_id_of(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def is_live(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def derive(bundle_path: str, version: str) -> dict:
    raw_bytes = open(bundle_path, "rb").read()
    bundle = json.loads(raw_bytes)
    objects = bundle["objects"]

    techniques = [o for o in objects if o.get("type") == "attack-pattern" and is_live(o)]
    intrusion_sets = [o for o in objects if o.get("type") == "intrusion-set" and is_live(o)]
    relationships = [o for o in objects if o.get("type") == "relationship" and is_live(o)]

    log.info(
        "live: techniques=%d groups=%d relationships=%d",
        len(techniques), len(intrusion_sets), len(relationships),
    )
    # Sanity check on raw object counts — expect roughly:
    # techniques 600-900, groups 130-200, relationships 15000-30000
    if len(techniques) < 100 or len(intrusion_sets) < 20 or len(relationships) < 1000:
        raise ValueError(
            f"Object counts look wrong for an Enterprise ATT&CK bundle "
            f"(techniques={len(techniques)}, groups={len(intrusion_sets)}, "
            f"relationships={len(relationships)}). Wrong file?"
        )

    # --- Step 4: ID maps ---
    stix_to_attack, attack_to_stix = {}, {}
    for t in techniques:
        aid = attack_id_of(t)
        if aid:
            stix_to_attack[t["id"]] = aid
            attack_to_stix[aid] = t["id"]
    live_group_ids = {g["id"] for g in intrusion_sets}

    # --- validate the category map BEFORE counting ---
    bad = [(c, t) for c, ts in CATEGORY_TECHNIQUE_MAP.items() for t in ts if "." in t]
    if bad:
        raise ValueError(f"sub-technique IDs not allowed in category map: {bad}")
    missing = [
        (c, t) for c, ts in CATEGORY_TECHNIQUE_MAP.items() for t in ts
        if t not in attack_to_stix
    ]
    if missing:
        raise ValueError(f"technique IDs not found in bundle {version}: {missing}")

    # --- Step 5: distinct groups per technique (sets, never counters) ---
    technique_groups = defaultdict(set)
    for rel in relationships:
        if rel.get("relationship_type") != "uses":
            continue
        src, tgt = rel.get("source_ref", ""), rel.get("target_ref", "")
        if not src.startswith("intrusion-set--") or not tgt.startswith("attack-pattern--"):
            continue
        if src not in live_group_ids:
            continue
        aid = stix_to_attack.get(tgt)
        if aid:
            technique_groups[aid].add(src)

    # --- Step 6: roll sub-techniques up to parents via set union ---
    rolled = defaultdict(set)
    for aid, groups in technique_groups.items():
        rolled[aid.split(".")[0]] |= groups
    counts = {aid: len(g) for aid, g in rolled.items()}

    # --- Step 8: raw category weights (sum + mean sensitivity check) ---
    raw = {
        c: sum(counts.get(t, 0) for t in tids)
        for c, tids in CATEGORY_TECHNIQUE_MAP.items()
    }
    raw_mean = {
        c: sum(counts.get(t, 0) for t in tids) / len(tids)
        for c, tids in CATEGORY_TECHNIQUE_MAP.items()
    }

    # --- Step 9: normalize to [S_MIN, 1.00] ---
    lo, hi = min(raw.values()), max(raw.values())
    if hi == lo:
        raise ValueError("all categories have identical raw weights — mapping is broken")
    severity = {
        c: round(S_MIN + (1.0 - S_MIN) * (v - lo) / (hi - lo), 4)
        for c, v in raw.items()
    }

    # --- Step 10: sanity gates ---
    assert severity["apt"] == max(severity.values()), \
        "APT must be highest — check the apt technique list"
    assert severity["ransomware"] > severity["scanner"], \
        "ransomware must outrank scanning"
    assert severity["botnet_c2"] > severity["cryptominer"], \
        "C2 must outrank cryptomining"
    assert all(S_MIN <= v <= 1.00 for v in severity.values()), "weights out of range"
    assert abs(max(severity.values()) - 1.0) < 1e-9, "top category must normalize to 1.0"
    assert abs(min(severity.values()) - S_MIN) < 1e-9, "bottom category must normalize to S_MIN"

    for c in sorted(raw, key=raw.get, reverse=True):
        log.info(
            "%-16s raw=%4d mean=%6.2f severity=%.4f",
            c, raw[c], raw_mean[c], severity[c],
        )

    return {
        "config_version": f"sev-{datetime.date.today().isoformat()}",
        "attack_bundle_version": version,
        "attack_bundle_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "derived_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "method": (
            "distinct intrusion-set count per category technique set, "
            "sum-aggregated, min-max normalized to [0.10, 1.00]"
        ),
        "s_min": S_MIN,
        "weights": severity,
        "raw_counts": raw,
        "raw_counts_mean": {c: round(v, 3) for c, v in raw_mean.items()},
        "per_technique_group_counts": {
            t: counts.get(t, 0)
            for ts in CATEGORY_TECHNIQUE_MAP.values() for t in ts
        },
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: derive_severity.py <bundle_path.json> <version>", file=sys.stderr)
        sys.exit(1)

    bundle_path, version = sys.argv[1], sys.argv[2]
    out = derive(bundle_path, version)

    os.makedirs("config", exist_ok=True)
    with open("config/severity_weights.json", "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)

    log.info("wrote config/severity_weights.json")
