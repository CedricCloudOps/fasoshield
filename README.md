# FasoShield

Plateforme nationale d'analyse de menaces mobiles : moteur de scan d'APK,
API de réputation de fichiers, gouvernance des signatures, partage avec les
CERT partenaires et agent antivirus Android souverain.

Conçue pour le paysage de menaces ouest-africain : fausses applications
mobile money, vol d'OTP par interception SMS, trojans bancaires à overlay et
droppers diffusés hors des stores officiels. Voir
[docs/ROADMAP.md](docs/ROADMAP.md) pour le cadrage complet.

## Composants

- **Moteur d'analyse** (`fasoshield.engine`) — pipeline quatre couches :
  blocklist SHA-256 (fichier **et** certificat de signature), YARA (fichier
  brut + DEX extraits), analyse statique Androguard, heuristiques
  comportementales. Verdict `CLEAN` / `SUSPICIOUS` / `MALICIOUS` avec score et
  rapport JSON.
- **API plateforme** (`fasoshield.api`) — FastAPI : soumission d'APK (analyse
  immédiate ou différée selon la taille), réputation par hash (chemin chaud des
  agents mobiles), mises à jour delta des signatures, télémétrie anonymisée.
- **Console SOC** (`/console`) — tableau de bord des détections, workflow de
  revue des signatures, journal d'audit et exports, protégée par une identité
  analyste distincte des clés d'agent.
- **Gouvernance des signatures** (`fasoshield.governance`) — cycle
  `DRAFT → REVIEW → PUBLISHED`, règle des quatre yeux, traçabilité complète.
- **Partage de renseignement** (`fasoshield.intel`) — bundles STIX 2.1 et
  événements MISP à destination des CERT partenaires.
- **CLI analyste** (`fasoshield.cli`) — scan local, lookup, gestion de la base
  de signatures, comptes, propositions, exports, worker. Codes de sortie
  shell : 0 clean, 1 suspect, 2 malveillant.
- **Signatures** (`signatures/`) — règles YARA nationales et registre des
  applications financières officielles (épinglage de certificat).
- **Agent Android** (`android/`) — application Kotlin : scan on-device des
  applications installées, base de signatures locale synchronisée en delta,
  alertes de désinstallation. Voir [android/README.md](android/README.md).

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

# API + console
make run           # http://127.0.0.1:8000/docs
```

Créer le premier compte de console, puis se connecter sur
`http://127.0.0.1:8000/console` :

```bash
fasoshield account create --username admin --role admin
```

> En HTTP simple, positionner `FASOSHIELD_SESSION_COOKIE_SECURE=false` sinon le
> navigateur ne renverra jamais le cookie de session.

Vérification bout-en-bout avec le fichier de test EICAR (inoffensif,
standard de l'industrie antivirus) :

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
fasoshield scan /tmp/eicar.com   # verdict: MALICIOUS
```

## Deux identités, deux portées

| | Agents mobiles | Analystes |
|---|---|---|
| Authentification | Clé d'API partagée (`X-API-Key`) | Compte nominatif, session `HttpOnly`, ou SSO |
| Accès | réputation, mises à jour de signatures, télémétrie, dépôt d'échantillon | console, statistiques, workflow de signatures, exports, comptes |
| Rôles | — | `viewer` < `analyst` < `admin` |

Une clé d'agent vit sur des milliers de téléphones : elle n'ouvre donc ni la
console, ni la vue nationale de la menace, ni les exports.

## Cycle de vie d'une signature

```
DRAFT ──submit──> REVIEW ──approve──> PUBLISHED ──> agents (sync delta)
                     └────reject────> REJECTED
```

Aucune écriture directe dans la blocklist. L'auteur d'une proposition ne peut
pas l'approuver : un faux positif sur une application de monnaie électronique
couperait des milliers d'usagers de leurs fonds, la décision exige deux
analystes. Chaque transition est écrite au journal d'audit.

```bash
fasoshield proposal list --status REVIEW
fasoshield proposal show 12
```

## Partage avec les CERT partenaires

```bash
fasoshield intel stix -o bundle.json     # STIX 2.1
fasoshield intel misp -o event.json      # événement MISP
```

Les identifiants d'objets sont dérivés de l'indicateur lui-même : réexporter le
même IOC met à jour l'objet chez le partenaire au lieu de le dupliquer. Aucune
donnée de télémétrie n'est exportée.

## Configuration

Variables d'environnement préfixées `FASOSHIELD_` (voir
[.env.example](.env.example)) : clés d'API agents, URL PostgreSQL, stockage de
quarantaine, identité analyste, durcissement. Sans configuration, l'API tourne
en mode développement sur SQLite.

## Qualité

```bash
make lint          # ruff
make test          # pytest + couverture
make security      # bandit + pip-audit
```

## Documentation

- [docs/ROADMAP.md](docs/ROADMAP.md) — cadrage, architecture, phases
- [docs/DEPLOIEMENT.md](docs/DEPLOIEMENT.md) — production, montée en charge, distribution de l'agent
- [docs/SECURITE.md](docs/SECURITE.md) — modèle de menaces, contrôles, risques résiduels
- [docs/CONFORMITE.md](docs/CONFORMITE.md) — AIPD et registre des traitements
- [docs/presentation/](docs/presentation/) — générateur du dossier de présentation ; le
  PDF n'est pas versionné, il est reconstruit par la CI et publié en artefact

## Licence

MIT — voir [LICENSE](LICENSE).
