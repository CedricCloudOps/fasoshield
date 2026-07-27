# FasoShield — Feuille de route

Plateforme nationale de protection contre les menaces mobiles : moteur
d'analyse d'APK, réputation de fichiers, distribution de signatures et
télémétrie anonymisée, complétés à terme par un agent Android grand public.

## Contexte et problème

Le paiement mobile est l'infrastructure financière dominante en Afrique de
l'Ouest. Les campagnes observées exploitent trois vecteurs principaux :

1. **Fausses applications financières** — clones d'Orange Money, Moov Money ou
   Wave diffusés hors des stores officiels (liens WhatsApp/Telegram, boutiques
   alternatives), qui volent le code PIN et vident les comptes.
2. **Vol d'OTP par interception SMS** — malware demandant `RECEIVE_SMS` pour
   capter les codes de validation des transactions.
3. **Smishing** — SMS en français usurpant les opérateurs, pointant vers des
   kits de phishing ou des APK malveillants.

Les antivirus commerciaux traitent mal ce paysage : signatures orientées
menaces globales, pas de registre des applications financières locales, pas de
règles sur les leurres en français, télémétrie exportée hors du territoire.
FasoShield répond par une plateforme souveraine : signatures nationales,
registre officiel des applications financières, données hébergées localement.

## Architecture cible

    +-------------------+        HTTPS         +----------------------------+
    |  Agent Android    | <------------------> |  API FasoShield            |
    |  (Kotlin)         |  reputation/updates  |  (FastAPI)                 |
    |  - scan installs  |                      |  - moteur d'analyse        |
    |  - base locale    |                      |  - blocklist SHA-256       |
    |  - alertes        |                      |  - règles YARA             |
    +-------------------+                      |  - registre apps officielles|
                                               +-------------+--------------+
    +-------------------+                                    |
    |  CLI analyste     | ---------------------------------> |
    |  (CERT national)  |        scan local / imports        |
    +-------------------+                                    v
                                               +----------------------------+
    +-------------------+                      |  PostgreSQL + quarantaine  |
    |  Console SOC      | <------------------- |  (échantillons, télémétrie)|
    |  (phase 4)        |     statistiques     +----------------------------+
    +-------------------+

## Phases

### Phase 1 — Moteur d'analyse (fait)

Pipeline en quatre couches, de la moins à la plus coûteuse :

1. lookup SHA-256 contre la blocklist nationale ;
2. YARA sur le fichier brut **et** sur chaque `classes*.dex` extrait
   (le DEX est compressé dans l'APK, invisible sans extraction) ;
3. analyse statique Androguard : manifeste, permissions, certificat de
   signature, composants exportés ;
4. heuristiques comportementales : combinaisons de permissions (interception
   SMS + réseau, overlay, profil spyware, dropper), usurpation d'applications
   financières (paquet identique signé par un certificat inconnu, paquets
   lookalike, marque dans le libellé), hygiène du manifeste.

Verdict : `CLEAN` / `SUSPICIOUS` / `MALICIOUS`, score 0-100, rapport JSON
complet. CLI analyste avec codes de sortie shell (0/1/2).

Critère de sortie : suite de tests verte, détection EICAR bout-en-bout.

### Phase 2 — API plateforme (fait)

- `POST /v1/scan` — soumission d'APK, quarantaine des échantillons détectés ;
- `GET /v1/reputation/{sha256}` — chemin chaud des agents : verdict sans
  upload (économie de données mobiles) ;
- `GET /v1/signatures/version` + `/v1/signatures/updates?since=` —
  synchronisation delta de la blocklist embarquée ;
- `POST /v1/telemetry` — événements de détection anonymisés (UUID opaque,
  aucun MSISDN/IMEI) ;
- authentification par clé d'API agent (`X-API-Key`), SQLite en dev,
  PostgreSQL en production.

Critère de sortie : tests d'API verts, upload EICAR → verdict MALICIOUS →
réputation servie depuis l'historique.

### Phase 3 — Agent Android (à venir)

- Kotlin, minSdk 24 ; scan des applications installées
  (`PackageManager`), détection des nouvelles installations
  (`ACTION_PACKAGE_ADDED`), hash APK → `/v1/reputation` ;
- base de signatures embarquée (Room) synchronisée en delta, mode hors-ligne
  complet ;
- alertes utilisateur : notification + écran de détail (permissions, raisons
  du verdict, procédure de désinstallation) ;
- prérequis poste de dev : Android Studio + JDK 17.

Critère de sortie : détection locale d'un APK de test signé EICAR-like sans
connexion réseau, puis remontée de télémétrie à la reconnexion.

### Phase 4 — Console SOC (fait)

- tableau de bord des détections servi par l'API (`GET /console`) : KPI
  corpus/terrain, répartition régionale, chronologie 14 jours, top menaces et
  détections récentes, alimenté par `GET /v1/stats/overview` (agrégations
  SQLAlchemy sur la télémétrie et l'historique de scans) ;
- **authentification analyste dédiée**, distincte des clés d'agent : comptes
  nominatifs (scrypt 64 Mio), sessions serveur stockées hachées, rôles
  `viewer` / `analyst` / `admin`, mode SSO par en-tête pour un déploiement
  derrière une passerelle OIDC. Une clé d'agent, présente sur des milliers de
  téléphones, n'ouvre ni la console, ni les statistiques, ni les exports ;
- **cycle de vie des signatures** `DRAFT → REVIEW → PUBLISHED / REJECTED`, avec
  justification obligatoire et **règle des quatre yeux** : l'auteur d'une
  proposition ne peut pas la valider, y compris s'il est administrateur ;
- **journal d'audit** append-only de toute action analyste (acteur, action,
  cible, adresse IP), consultable depuis la console ;
- **exports MISP et STIX 2.1** vers les CERT partenaires, avec identifiants
  d'objets dérivés de l'indicateur — un réexport met à jour l'objet chez le
  partenaire au lieu de le dupliquer.

### Phase 5 — Durcissement et déploiement (fait, hors audit externe)

- **montée en charge** : PostgreSQL en production, quarantaine sur stockage
  objet (backend abstrait, S3 optionnel pour rester déployable sur une
  infrastructure souveraine sans cloud), file de scan asynchrone au-delà d'un
  seuil de taille. La table `scan_jobs` sert de file : un worker prend un
  travail par `UPDATE … WHERE status = 'QUEUED'`, ce qui permet plusieurs
  instances sans courtier de messages ;
- **durcissement du transport** : CSP stricte sans origine externe et à nonce
  régénéré par réponse, en-têtes de sécurité, HSTS, limitation de débit en
  seau à jetons par appelant, CORS fermé par défaut, identifiant de requête
  propagé et journalisé ;
- **signature de l'APK par l'autorité nationale** : configuration release
  adossée à un keystore externe au dépôt (v1+v2+v3), build non signé plutôt que
  signé en debug si aucun keystore n'est fourni ; procédure de publication et
  de vérification d'empreinte documentée ;
- **conformité protection des données personnelles** : AIPD et registre des
  traitements ([docs/CONFORMITE.md](CONFORMITE.md)), modèle de menaces et
  posture de sécurité ([docs/SECURITE.md](SECURITE.md)) ;
- **reste ouvert** : l'audit de sécurité externe de l'API et de l'agent, qui
  est par nature un travail de tiers. Le périmètre attendu est énoncé dans
  [docs/SECURITE.md](SECURITE.md) §5. La publication sur le canal officiel
  dépend de la remise de la clé de signature par l'autorité.

## Risques identifiés

| Risque | Impact | Mitigation |
|---|---|---|
| Faux positifs sur applications légitimes | Perte de confiance utilisateur | Registre officiel + seuils conservateurs + revue humaine avant blocklist |
| Contournement par obfuscation du DEX | Détection dégradée | Couche heuristique indépendante du contenu DEX ; règles sur le manifeste |
| Fuite de la base de signatures | Les attaquants testent leurs APK | Clés d'API par agent, distribution delta, rotation |
| Données personnelles dans la télémétrie | Risque juridique | Anonymisation à la source, schéma sans identifiant direct, revue DPIA |
