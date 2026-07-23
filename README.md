# FasoShield

Plateforme nationale d'analyse de menaces mobiles : moteur de scan d'APK,
API de réputation de fichiers et distribution de signatures pour un agent
antivirus Android souverain.

Conçue pour le paysage de menaces ouest-africain : fausses applications
mobile money, vol d'OTP par interception SMS, trojans bancaires à overlay et
droppers diffusés hors des stores officiels. Voir
[docs/ROADMAP.md](docs/ROADMAP.md) pour le cadrage complet.

## Composants

- **Moteur d'analyse** (`fasoshield.engine`) — pipeline quatre couches :
  blocklist SHA-256, YARA (fichier brut + DEX extraits), analyse statique
  Androguard, heuristiques comportementales. Verdict `CLEAN` /
  `SUSPICIOUS` / `MALICIOUS` avec score et rapport JSON.
- **API plateforme** (`fasoshield.api`) — FastAPI : soumission d'APK,
  réputation par hash (chemin chaud des agents mobiles), mises à jour delta
  des signatures, télémétrie anonymisée.
- **CLI analyste** (`fasoshield.cli`) — scan local, lookup, gestion de la
  base de signatures. Codes de sortie shell : 0 clean, 1 suspect, 2 malveillant.
- **Signatures** (`signatures/`) — règles YARA nationales et registre des
  applications financières officielles (épinglage de certificat).
- **Agent Android** (`android/`) — application Kotlin (phase 3) : scan
  on-device des applications installées, base de signatures locale synchronisée
  en delta, alertes de désinstallation. Voir [android/README.md](android/README.md).

## Démarrage

Prérequis : Python 3.10 ou supérieur (`make install PYTHON=python3.14` pour
choisir l'interpréteur).

```bash
make install
source .venv/bin/activate
make seed          # importe les signatures d'amorçage
make test

# scan local
fasoshield scan chemin/vers/app.apk
fasoshield scan chemin/vers/app.apk --json

# API
make run           # http://127.0.0.1:8000/docs
```

Vérification bout-en-bout avec le fichier de test EICAR (inoffensif,
standard de l'industrie antivirus) :

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
fasoshield scan /tmp/eicar.com   # verdict: MALICIOUS
```

## Configuration

Variables d'environnement préfixées `FASOSHIELD_` (voir
[.env.example](.env.example)) : clés d'API agents, URL PostgreSQL,
répertoires de données et de signatures, taille maximale d'upload.
Sans configuration, l'API tourne en mode développement sur SQLite.

## Qualité

```bash
make lint          # ruff
make test          # pytest + couverture
make security      # bandit + pip-audit
```

## Licence

MIT — voir [LICENSE](LICENSE).
