# FasoShield — Guide de déploiement

Du poste de développement à l'infrastructure nationale.

---

## 1. Développement local

```bash
make install
source .venv/bin/activate      # Windows : .venv\Scripts\activate
make seed
make test
make run                        # http://127.0.0.1:8000/docs
```

Sans configuration, la plateforme tourne sur SQLite, sans authentification
d'agent, avec la quarantaine dans `data/quarantine`. Ce mode est **réservé au
développement** : il n'exige aucune clé.

Créer le premier compte de console :

```bash
fasoshield account create --username admin --role admin
```

La console est ensuite accessible sur `http://127.0.0.1:8000/console`.

> En HTTP simple, positionner `FASOSHIELD_SESSION_COOKIE_SECURE=false`, sinon
> le navigateur ne renverra jamais le cookie de session.

## 2. Configuration de production

Toutes les variables sont préfixées `FASOSHIELD_` (voir `.env.example`).

| Variable | Rôle | Valeur de production |
|---|---|---|
| `DATABASE_URL` | Base plateforme | `postgresql+psycopg://…` |
| `API_KEYS` | Clés des agents mobiles | liste séparée par des virgules, **non vide** |
| `DATA_DIR` | Données locales | `/var/lib/fasoshield` |
| `SIGNATURES_DIR` | Règles YARA et graines | `/etc/fasoshield/signatures` |
| `QUARANTINE_URL` | Stockage des échantillons | `s3://fasoshield-quarantine/samples` |
| `MAX_UPLOAD_BYTES` | Plafond de dépôt | 209715200 (200 Mio) |
| `ASYNC_SCAN_THRESHOLD_BYTES` | Seuil de mise en file | 16777216 (16 Mio) |
| `SESSION_COOKIE_SECURE` | Cookie HTTPS uniquement | `true` |
| `SESSION_TTL_MINUTES` | Durée de session analyste | 720 |
| `RATE_LIMIT_PER_MINUTE` | Débit par appelant | 120 |
| `TRUSTED_PROXY_COUNT` | Sauts de proxy de confiance | nombre exact de reverse proxies |
| `CORS_ORIGINS` | Origines autorisées | vide sauf console distincte |
| `INTEL_ORG_NAME` | Producteur des exports | nom officiel du CERT |
| `INTEL_TLP` | Marquage par défaut | `amber` |

**`TRUSTED_PROXY_COUNT` mérite une attention particulière.** À 0, l'adresse
client provient de la connexion TCP. Au-delà, la plateforme lit l'en-tête
`X-Forwarded-For` en ne remontant que du nombre de sauts déclaré. Une valeur
trop grande permettrait à un appelant de forger l'adresse consignée dans le
journal d'audit.

### Base de données

Le schéma est créé au démarrage (`create_all`). Pour une exploitation
pluriannuelle avec évolutions de schéma, adosser un outil de migration
(Alembic) reste à prévoir : c'est un choix d'exploitation, pas un manque
fonctionnel, mais il doit être tranché avant la première montée de version en
production.

La base de signatures (`signatures.db`, SQLite) est distincte de la base
plateforme : elle est petite, en lecture quasi exclusive, et se met à niveau
seule (ajout de la colonne `cert_sha256` sur une base ancienne, sans
réimportation de la blocklist nationale).

## 3. Conteneur

```bash
docker build -t fasoshield:0.1.0 .
docker run --rm -p 8000:8000 \
  -e FASOSHIELD_API_KEYS="$AGENT_KEYS" \
  -e FASOSHIELD_DATABASE_URL="$PG_URL" \
  -v /var/lib/fasoshield:/var/lib/fasoshield \
  fasoshield:0.1.0
```

## 4. Montée en charge

L'API est sans état ; elle se réplique derrière un répartiteur de charge.

La file de scan différé est portée par la table `scan_jobs` : un worker prend
un travail par `UPDATE … WHERE status = 'QUEUED'`, que la base sérialise. Deux
conséquences pratiques :

- chaque instance d'API embarque un worker, donc un déploiement mono-serveur
  n'a besoin de rien d'autre ;
- un déploiement réparti peut lancer des workers dédiés
  (`fasoshield worker`) sans courtier de messages, et sans risque de double
  traitement.

En répartition, la quarantaine **doit** passer en stockage objet
(`QUARANTINE_URL=s3://…`, extra `s3`), sans quoi un échantillon analysé par une
instance sera introuvable depuis une autre.

```bash
pip install "fasoshield[s3]"
fasoshield worker            # worker autonome
fasoshield worker --once     # vidange unique, pour un ordonnanceur
```

Les identifiants S3 proviennent des variables d'environnement AWS standard :
aucun secret de stockage ne transite par la configuration applicative.

## 5. Reverse proxy et SSO

L'API doit être exposée derrière un terminaison TLS. Configuration attendue :

- HTTPS obligatoire, HSTS activé côté application (`HSTS_ENABLED=true`) ;
- transmission de `X-Forwarded-For`, avec `TRUSTED_PROXY_COUNT` aligné ;
- taille maximale de corps cohérente avec `MAX_UPLOAD_BYTES`.

Pour l'authentification analyste par passerelle OIDC :

```bash
FASOSHIELD_SSO_USER_HEADER=X-Auth-User
FASOSHIELD_SSO_ROLE_HEADER=X-Auth-Role
FASOSHIELD_SSO_DEFAULT_ROLE=viewer
```

**Condition impérative** : dans ce mode, l'API ne doit être joignable que par
la passerelle. Le réseau doit interdire tout accès direct, faute de quoi
n'importe qui pourrait forger l'en-tête et obtenir un rôle. Le port applicatif
n'écoute donc que sur l'interface interne, et la passerelle supprime l'en-tête
entrant avant de poser le sien.

## 6. Distribution de l'agent

1. Générer la clé de signature nationale et la conserver dans le magasin scellé
   de l'autorité (HSM ou support hors ligne).
2. Renseigner `android/keystore.properties` sur la machine de build, ou les
   variables `FASOSHIELD_KEYSTORE`, `FASOSHIELD_KEYSTORE_PASSWORD`,
   `FASOSHIELD_KEY_ALIAS`, `FASOSHIELD_KEY_PASSWORD` en intégration continue.
   Ces fichiers sont ignorés par git.
3. Construire : `./gradlew :app:bundleRelease`.
4. Vérifier l'empreinte avant publication :
   `apksigner verify --print-certs app-release.apk`.
5. Publier l'empreinte du certificat sur le site officiel : c'est ce qui permet
   à un utilisateur de vérifier qu'il installe le vrai agent.
6. Publier sur le canal officiel (magasin d'applications et site de l'autorité).

Sans keystore configuré, le build release produit un artefact **non signé** :
c'est délibéré, une absence de signature se remarque immédiatement.

## 7. Exploitation courante

```bash
make security                       # bandit + pip-audit
fasoshield db stats                 # état de la base de signatures
fasoshield proposal list --status REVIEW
fasoshield intel stix -o bundle.json
fasoshield account list
```

Points de supervision recommandés :

- `GET /health` pour les sondes du répartiteur ;
- profondeur de la file `scan_jobs` en état `QUEUED` ;
- nombre de propositions en `REVIEW` depuis plus de 48 h ;
- taux de réponses 429, révélateur d'un agent mal configuré ;
- croissance du volume de quarantaine.
