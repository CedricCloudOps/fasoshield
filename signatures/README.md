# Base de signatures FasoShield

## Contenu

- `yara/` — règles YARA du socle national. Chaque règle déclare
  `meta.description` et `meta.severity` (INFO/LOW/MEDIUM/HIGH/CRITICAL).
- `hashes/blocklist.seed.csv` — amorce de la blocklist SHA-256
  (format : `sha256,threat_name,source`). Seule l'entrée EICAR est versionnée ;
  les IOC opérationnels sont importés depuis les flux du CERT (export MISP,
  partenaires) et ne transitent jamais par le dépôt Git.
- `hashes/official_apps.seed.csv` — registre des applications financières
  officielles (format : `package_name,label,cert_sha256`).

## Provisionnement du registre officiel

Le champ `cert_sha256` doit être renseigné à partir de l'APK officiel de
chaque éditeur, jamais depuis une source secondaire :

1. Récupérer l'APK depuis le Play Store (ou remis directement par l'éditeur).
2. `fasoshield scan chemin/vers/app-officielle.apk --json` — relever le champ
   `facts.cert_sha256`.
3. Reporter la valeur dans le CSV puis réimporter :
   `fasoshield db import-official signatures/hashes/official_apps.seed.csv`.

Tant que `cert_sha256` est vide, le paquet est reconnu comme officiel pour la
détection de lookalikes, mais le contrôle d'usurpation de certificat est
inactif pour cette entrée.

## Import

```
fasoshield db import signatures/hashes/blocklist.seed.csv
fasoshield db import-official signatures/hashes/official_apps.seed.csv
```

Chaque import incrémente la version de la base (horodatage UTC) ; les agents
mobiles se synchronisent ensuite en delta via `GET /v1/signatures/updates`.
