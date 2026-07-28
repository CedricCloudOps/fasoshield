# FasoShield — Agent Android

Agent mobile de la plateforme FasoShield (phase 3). Il analyse les applications
installées **hors-ligne** et interroge la plateforme uniquement pour la
réputation par hash et la synchronisation des signatures.

## Fonctionnalités

- **Scan on-device** des applications installées via `PackageManager` :
  permissions, certificat de signature, source d'installation, SDK cible.
- **Heuristiques portées du moteur serveur** (mêmes identifiants de règles,
  mêmes sévérités) : usurpation d'applications mobile money, interception de
  SMS/OTP, superposition d'écran, profil spyware, dropper, sideload.
- **Base de signatures locale** (Room) synchronisée en **delta** depuis
  `GET /v1/signatures/updates` — fonctionnement complet sans réseau. Chaque
  bundle est **signé par la plateforme** (ECDSA P-256) et vérifié avant d'être
  appliqué : un delta non signé ou altéré est rejeté et l'agent reste sur la
  dernière base qu'il a pu vérifier.
- **Réputation par hash** pour les seules applications à provenance non fiable :
  le SHA-256 de l'APK est comparé à la base nationale via
  `GET /v1/reputation/{sha256}`, ce qui donne accès aux couches du moteur
  serveur (YARA, analyse DEX, historique) **sans jamais envoyer de fichier**.
- **Détection des nouvelles installations** via `BroadcastReceiver`
  (`PACKAGE_ADDED` / `PACKAGE_REPLACED`), scan délégué à un `WorkManager`.
- **Scan périodique** quotidien (WorkManager), ré-armé après redémarrage.
- **Alertes** : notification haute priorité avec action de désinstallation.
- **Télémétrie anonymisée** : UUID opaque auto-généré, aucun IMEI/MSISDN.

## Architecture du module

```
scan/     Modèles, heuristiques, réputation, AppScanner (PackageManager)
security/ Vérification de la signature des bundles (BundleVerifier)
data/     Room (blocklist, registre officiel, détections), SignatureStore,
          AgentRepository (sync + scan + télémétrie)
network/  Contrat Retrofit + client OkHttp (clé d'API agent)
work/     ScanWorker, receivers (installation, boot), notifications
ui/       MainActivity (Compose) + ScanViewModel
util/     Prefs (agent id opaque, version des signatures)
```

## Prérequis de build

- **Android Studio Ladybug (2024.2)** ou supérieur
- **JDK 17**
- Android SDK 35, minSdk 24

Le fichier `local.properties` (chemin du SDK) est propre à chaque poste et n'est
pas versionné ; Android Studio le régénère à l'ouverture du projet, ou bien
`echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties` en ligne de
commande.

## Build et tests

```bash
# Tests unitaires JVM (heuristiques, scoring) — sans émulateur
./gradlew :app:testDebugUnitTest

# APK de debug
./gradlew :app:assembleDebug

# Installer sur un appareil/émulateur connecté
./gradlew :app:installDebug
```

En debug, l'agent pointe par défaut vers `http://10.0.2.2:8000/` — l'alias de la
machine hôte **vu depuis l'émulateur**. Sur un appareil physique cette adresse
n'existe pas : il faut soit rediriger le port par USB, soit viser l'adresse de
l'hôte sur le réseau local.

```bash
# Appareil physique, via le tunnel USB (aucune configuration réseau)
adb reverse tcp:8000 tcp:8000
./gradlew :app:installDebug -PfasoshieldDebugApiUrl=http://127.0.0.1:8000/

# Appareil physique, via le réseau local
./gradlew :app:installDebug -PfasoshieldDebugApiUrl=http://192.168.1.20:8000/
```

### Clé de vérification des signatures

La clé publique qui valide les bundles est fournie au build :

```bash
# Sur la plateforme
fasoshield keys generate --output data/bundle-signing.pem

# Sur la machine de build (la commande ci-dessus affiche la valeur exacte)
./gradlew :app:assembleRelease -PfasoshieldSignatureKey=MFkwEwYHKoZIzj0CAQ...
```

Sans cette propriété, le build émet un avertissement et produit un agent qui
accepte les bundles non signés — acceptable face à une plateforme de
développement locale, jamais pour une distribution.

La propriété peut aussi être posée dans le `gradle.properties` personnel du
développeur. Elle n'alimente que le type de build `debug` ; la release conserve
l'URL de production définie dans `app/build.gradle.kts` (`API_BASE_URL`).

Le HTTP en clair nécessaire à ce serveur local est autorisé par
`app/src/debug/res/xml/network_security_config.xml`, qui appartient au seul
source set `debug` : la release garde le comportement par défaut de la
plateforme, HTTPS uniquement.

## Tests

Les tests JVM (`app/src/test`) valident les heuristiques et le scoring — la
même logique métier que la suite Python du moteur serveur, pour garantir que
verdict local et verdict plateforme restent cohérents.
