# MITRE ATT&CK bundle

The bundle is not stored in this repository (about 50 MB). Download Enterprise ATT&CK 19.1:

```bash
curl -L -o data/mitre/enterprise-attack-19.1.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json
sha256sum -c data/mitre/enterprise-attack-19.1.sha256
python tools/derive_severity.py data/mitre/enterprise-attack-19.1.json 19.1
```

The checksum must match for the weights in `config/severity_weights.json` to be reproduced exactly.
