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
  `GET /v1/signatures/updates` — fonctionnement complet sans réseau.
- **Détection des nouvelles installations** via `BroadcastReceiver`
  (`PACKAGE_ADDED` / `PACKAGE_REPLACED`), scan délégué à un `WorkManager`.
- **Scan périodique** quotidien (WorkManager), ré-armé après redémarrage.
- **Alertes** : notification haute priorité avec action de désinstallation.
- **Télémétrie anonymisée** : UUID opaque auto-généré, aucun IMEI/MSISDN.

## Architecture du module

```
scan/     Modèles, heuristiques, AppScanner (lecture PackageManager)
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

> Ces outils ne sont pas installés sur la machine de développement actuelle.
> Le code est complet et structuré pour compiler, mais la compilation et
> l'exécution des tests doivent être faites après installation d'Android Studio.

## Build et tests

```bash
# Tests unitaires JVM (heuristiques, scoring) — sans émulateur
./gradlew :app:testDebugUnitTest

# APK de debug
./gradlew :app:assembleDebug

# Installer sur un appareil/émulateur connecté
./gradlew :app:installDebug
```

En debug, l'agent pointe vers `http://10.0.2.2:8000/` (API FastAPI lancée sur
la machine hôte, accessible depuis l'émulateur). L'URL de production est
définie dans `app/build.gradle.kts` (`API_BASE_URL`).

## Tests

Les tests JVM (`app/src/test`) valident les heuristiques et le scoring — la
même logique métier que la suite Python du moteur serveur, pour garantir que
verdict local et verdict plateforme restent cohérents.
