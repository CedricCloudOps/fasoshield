# FasoShield — Protection des données personnelles

Analyse d'impact (AIPD) et registre des traitements. Ce document est le
livrable de conformité de la phase 5 ; il doit être revu par le responsable de
traitement avant toute mise en service auprès du public.

Cadre de référence : loi n° 001-2021/AN du 30 mars 2021 portant protection des
personnes à l'égard du traitement des données à caractère personnel au Burkina
Faso, et autorité de contrôle compétente (CIL). Les principes retenus
(minimisation, limitation des finalités, durée de conservation, sécurité) sont
communs à ce cadre et au RGPD, ce qui facilitera un partage ultérieur avec des
CERT européens.

> Ce document décrit le traitement tel que la plateforme est **conçue et
> implémentée**. Il ne remplace pas la validation juridique par le responsable
> de traitement ni la déclaration auprès de l'autorité de contrôle.

---

## 1. Nécessité d'une AIPD

Une analyse d'impact est requise dès lors qu'un traitement présente un risque
élevé pour les droits des personnes. Deux critères sont réunis ici :

- **traitement à grande échelle** — l'agent est destiné au parc national de
  téléphones ;
- **surveillance systématique** — l'agent examine en continu les applications
  installées sur l'appareil d'une personne.

L'AIPD est donc conduite alors même que le dispositif a été conçu pour ne
traiter aucune donnée directement identifiante.

## 2. Description du traitement

**Finalité.** Détecter et signaler les applications mobiles malveillantes
visant les comptes de monnaie électronique, et produire une statistique
nationale de la menace permettant d'orienter la réponse du CERT.

**Base légale.** Mission d'intérêt public de sécurité des systèmes
d'information, complétée par le consentement de l'utilisateur à l'installation
de l'agent et à l'envoi de télémétrie.

**Responsable de traitement.** L'autorité nationale opérant la plateforme.
**Sous-traitants.** Aucun sous-traitant hors du territoire : l'hébergement, la
base de données et la quarantaine sont nationaux.

## 3. Registre des traitements

| Traitement | Données | Origine | Finalité | Conservation | Base légale |
|---|---|---|---|---|---|
| Analyse d'échantillon | Empreinte SHA-256, nom de fichier, taille, faits statiques du manifeste, certificat de signature | Dépôt analyste ou console | Qualifier un échantillon | Illimitée (corpus national) | Intérêt public |
| Corpus d'échantillons | Fichier binaire mis en quarantaine | Dépôt analyste | Ré-examen, rétro-analyse | Illimitée | Intérêt public |
| Télémétrie de détection | UUID opaque d'agent, nom de paquet, verdict, nom de menace, région déclarative | Agent mobile | Statistique nationale | 24 mois glissants | Consentement |
| Comptes analystes | Identifiant, nom d'affichage, empreinte scrypt du mot de passe, rôle, horodatage de connexion | Saisie administrateur | Traçabilité des publications | Durée des fonctions + 12 mois | Intérêt public |
| Journal d'audit | Acteur, action, cible, adresse IP, horodatage | Console et CLI | Imputabilité des décisions | 36 mois | Obligation de traçabilité |
| Sessions console | Empreinte SHA-256 du jeton, identifiant, adresse IP | Connexion analyste | Authentification | Expiration de session (12 h par défaut) | Intérêt public |

## 4. Données que la plateforme ne collecte pas

Ce point est structurant : ces champs sont **absents du schéma de base de
données**, ils ne peuvent donc pas être collectés par simple changement de
configuration.

- Numéro de téléphone (MSISDN), IMEI, IMSI, numéro de série de l'appareil.
- Identité, adresse, compte bancaire ou de monnaie électronique.
- Contenu des SMS, journaux d'appels, contacts, position GPS.
- Historique de navigation, contenu applicatif.
- Adresse IP de l'appareil mobile dans les événements de télémétrie.

L'identifiant d'agent est un **UUID généré sur l'appareil**, sans lien avec un
identifiant matériel ou d'abonné. La région est une **donnée déclarative
grossière** (région administrative), choisie par l'utilisateur et destinée à la
seule cartographie de la menace.

## 5. Analyse des risques

| Risque | Impact pour la personne | Vraisemblance | Mesures en place |
|---|---|---|---|
| Ré-identification par corrélation UUID + région + paquet | Moyen | Faible | UUID sans lien matériel, région large, pas d'IP en télémétrie, pas de jointure possible avec un annuaire d'abonnés |
| Fuite de la base de télémétrie | Moyen | Faible | Aucune donnée identifiante à exfiltrer ; chiffrement au repos et TLS en transit |
| Faux positif privant l'utilisateur d'une application légitime | Élevé | Moyen | Registre des applications officielles, heuristiques conditionnées à la provenance, règle des quatre yeux avant toute publication, alerte non bloquante (l'agent n'a pas le droit de désinstaller) |
| Détournement de la console pour surveiller une personne | Élevé | Faible | Aucune vue par appareil : la console n'expose que des agrégats et les dernières détections sans identifiant d'agent ; toute consultation est auditée |
| Compromission d'un compte analyste | Élevé | Faible | scrypt 64 Mio, sessions stockées hachées et révocables, RBAC, journal d'audit, quatre yeux pour publier |
| Réutilisation d'une clé d'agent volée | Faible | Moyen | La clé d'agent n'ouvre ni la console, ni les statistiques, ni les exports ; limitation de débit par clé |

## 6. Droits des personnes

- **Information** — l'écran d'installation de l'agent présente la nature des
  données envoyées et leur finalité, avant tout envoi.
- **Consentement et retrait** — la télémétrie est activable et désactivable
  dans l'agent ; désactivée, l'agent continue de protéger l'appareil hors
  ligne. Le retrait n'entraîne aucune perte de fonctionnalité de sécurité.
- **Accès et effacement** — l'utilisateur peut lire son UUID d'agent dans
  l'application et en demander l'effacement ; la régénération locale de l'UUID
  rompt tout lien avec les événements passés.
- **Opposition** — la désinstallation de l'agent met fin à tout traitement.

## 7. Conclusion de l'analyse

Le traitement est proportionné à sa finalité. Le risque résiduel principal
n'est pas la vie privée mais le **faux positif** sur une application financière
légitime : il est traité par le registre des applications officielles, par le
conditionnement des heuristiques à la provenance de l'application, et par la
règle des quatre yeux qui interdit à un analyste de publier seul un indicateur.

Points à trancher par le responsable de traitement avant mise en service :

1. durée de conservation définitive du corpus d'échantillons (proposée :
   illimitée pour les échantillons malveillants, 12 mois pour les échantillons
   propres) ;
2. modalités de publication de la politique de confidentialité et de recueil du
   consentement dans le magasin de distribution ;
3. désignation du délégué à la protection des données et point de contact
   publié pour l'exercice des droits.
