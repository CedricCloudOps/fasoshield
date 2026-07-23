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

### Phase 4 — Console SOC

- tableau de bord des détections : familles, volumes, répartition régionale ;
- gestion du cycle de vie des signatures (proposition → revue → publication) ;
- exports MISP/STIX vers les CERT partenaires.

### Phase 5 — Durcissement et déploiement

- audit de sécurité externe de l'API et de l'agent ;
- signature de l'APK par l'autorité nationale, publication Play Store +
  canal de distribution officiel ;
- conformité protection des données personnelles (traitement anonymisé,
  registre des traitements, DPIA) ;
- montée en charge : PostgreSQL managé, stockage objet pour la quarantaine,
  file de scan asynchrone (les uploads > seuil passent en traitement différé).

## Risques identifiés

| Risque | Impact | Mitigation |
|---|---|---|
| Faux positifs sur applications légitimes | Perte de confiance utilisateur | Registre officiel + seuils conservateurs + revue humaine avant blocklist |
| Contournement par obfuscation du DEX | Détection dégradée | Couche heuristique indépendante du contenu DEX ; règles sur le manifeste |
| Fuite de la base de signatures | Les attaquants testent leurs APK | Clés d'API par agent, distribution delta, rotation |
| Données personnelles dans la télémétrie | Risque juridique | Anonymisation à la source, schéma sans identifiant direct, revue DPIA |
