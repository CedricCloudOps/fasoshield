# FasoShield — Modèle de menaces et posture de sécurité

Document de référence pour l'audit externe de la phase 5. Il énonce ce que la
plateforme protège, contre qui, par quels contrôles — et ce qui reste ouvert.

---

## 1. Biens à protéger

| Bien | Pourquoi il est convoité |
|---|---|
| Base de signatures | Y injecter une entrée permettrait de faire désinstaller massivement une application légitime ; en connaître le contenu permet à un attaquant de tester ses charges jusqu'à passer |
| Comptes analystes | Un compte suffit à voir la menace nationale ; deux comptes complices suffisent à publier |
| Corpus d'échantillons | Collection de malwares réels, réutilisable offensivement |
| Télémétrie | Cartographie de l'infection nationale, exploitable pour cibler les zones mal couvertes |
| Clé de signature de l'APK | La compromettre permet de distribuer une mise à jour malveillante de l'antivirus lui-même |

## 2. Attaquants considérés

- **A1 — Opérateur de fraude mobile money.** Motivé financièrement. Cherche à
  ne pas être détecté et à connaître le contenu de la blocklist.
- **A2 — Développeur d'application légitime malveillant.** Cherche à faire
  inscrire un concurrent sur la blocklist.
- **A3 — Analyste interne malintentionné.** Dispose déjà d'un accès légitime.
- **A4 — Attaquant réseau.** Interception, rejeu, déni de service sur l'API.
- **A5 — Attaquant sur l'appareil.** Application hostile installée à côté de
  l'agent, cherchant à le neutraliser ou à lire ses données.

## 3. Contrôles en place

### Séparation des identités

Deux systèmes d'authentification distincts, sans recouvrement :

- **Agents** — clé d'API partagée, portée limitée à `/v1/reputation`,
  `/v1/signatures/*`, `/v1/telemetry`, `/v1/scan`. Une clé qui vit sur des
  milliers de téléphones ne peut pas être considérée comme un secret : elle
  n'ouvre donc **ni la console, ni les statistiques, ni les exports**.
- **Analystes** — compte nominatif, mot de passe haché en scrypt (N=2^16, r=8,
  soit 64 Mio par calcul), session opaque stockée uniquement sous forme
  d'empreinte SHA-256, cookie `HttpOnly` + `SameSite=Lax` + `Secure`.

Un déploiement derrière une passerelle OIDC peut substituer l'en-tête SSO au
cookie. Ce mode n'est sûr que si l'API est **injoignable autrement que par la
passerelle** ; c'est une condition de déploiement, pas une option de confort.

### Gouvernance des signatures (contre A2 et A3)

Aucune écriture directe dans la blocklist. Tout indicateur passe par
`DRAFT → REVIEW → PUBLISHED`, avec :

- justification circonstanciée obligatoire (20 caractères minimum, refusée si
  vide) ;
- **règle des quatre yeux** : l'auteur d'une proposition ne peut ni l'approuver
  ni la rejeter, y compris s'il est administrateur ;
- journal d'audit append-only de chaque transition, avec acteur, cible et
  adresse IP.

### Réduction des faux positifs (contre A2)

- Registre national des applications financières officielles, avec épinglage du
  certificat de signature : une application dont le certificat correspond est
  exemptée des heuristiques d'usurpation.
- Côté agent, les heuristiques de permissions et d'hygiène ne s'appliquent
  **qu'aux applications de provenance non fiable**. Une messagerie installée
  depuis le Play Store lit légitimement les SMS ; la signaler noierait les
  vraies détections.
- L'agent **ne désinstalle jamais** : il alerte et propose la désinstallation à
  l'utilisateur, qui décide.

### Durcissement du transport (contre A4)

- En-têtes : `Content-Security-Policy` sans aucune origine externe (la console
  n'utilise aucun CDN), `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, HSTS.
- Le script et la feuille de style de la console portent un **nonce régénéré à
  chaque réponse**.
- Limitation de débit en seau à jetons, par clé d'API si présente (indexée sur
  une empreinte, jamais sur la clé en clair), sinon par adresse client.
- CORS fermé par défaut ; aucune origine tierce n'est autorisée sans
  configuration explicite.
- Identifiant de requête propagé et journalisé, sans chaîne de requête ni corps.

### Robustesse du moteur (contre A1)

- Le pipeline aboutit toujours : une archive corrompue ou un fichier non-APK
  produit tout de même un rapport, il n'existe pas d'entrée qui « fasse taire »
  le moteur.
- Les entrées DEX sont lues **avec un plafond mémoire** (64 Mio) et au plus dix
  fichiers, ce qui borne le coût d'une archive hostile.
- Les échecs d'analyse Androguard sont capturés et consignés dans le rapport au
  lieu d'interrompre le scan.
- Les tâches de scan différé isolent les échecs : un travail qui échoue est
  marqué `FAILED`, le worker continue.

### Chaîne de distribution (contre l'attaque sur la clé de signature)

- La configuration de signature release lit un keystore **externe au dépôt**
  (`keystore.properties` ou variables d'environnement), ignoré par git.
- Sans keystore configuré, le build release reste **non signé** plutôt que de
  retomber silencieusement sur la clé de debug : un artefact non signé se voit,
  un artefact signé avec la clé de debug ne se voit pas.
- Signatures v1 + v2 + v3 activées : v2/v3 pour la vérification de l'APK
  complet, v1 pour les appareils encore en API 24 du parc national.

## 4. Risques résiduels assumés

| Risque | Pourquoi il subsiste | Mesure compensatoire |
|---|---|---|
| Contournement du moteur par un malware inconnu | Aucun antivirus n'est exhaustif | Défense en profondeur : signature, YARA, statique, comportemental ; réactivité du CSIRT |
| Deux analystes complices publient un faux indicateur | Les quatre yeux protègent d'un acteur isolé, pas d'une collusion | Journal d'audit, revue périodique des publications, réversibilité |
| Vol de la clé d'agent | Elle est distribuée avec l'application | Portée volontairement réduite, limitation de débit, rotation possible |
| Déni de service applicatif | Le scan statique est coûteux par nature | File asynchrone au-delà d'un seuil, plafond de taille, limitation de débit |
| Analyse dynamique absente | Non implémentée à ce stade | Documentée comme extension : bac à sable d'exécution |

## 5. Points à couvrir par l'audit externe

1. Test d'intrusion authentifié de l'API et de la console (dont contournement
   de la règle des quatre yeux et élévation de privilège viewer → analyst).
2. Revue de l'implémentation cryptographique (scrypt, génération et cycle de
   vie des jetons de session).
3. Fuzzing du moteur d'analyse sur APK malformés.
4. Revue de l'agent Android : stockage local, surface d'attaque des receivers,
   résistance à une application hostile co-installée.
5. Revue de la chaîne de build et de distribution, de la génération de la clé à
   la publication.

## 6. Signalement de vulnérabilité

Une faille découverte dans FasoShield doit être signalée au CERT national par
canal privé, avec un délai de correction convenu avant divulgation publique. Le
point de contact et la clé de chiffrement associée sont à publier avant la mise
en service.
