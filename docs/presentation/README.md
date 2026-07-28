# Dossier de présentation

Générateur du document de présentation complet du projet (13 pages) : contexte
de menace, architecture, moteur d'analyse, agent Android, console SOC,
gouvernance des signatures, partage avec les CERT, exploitation, sécurité,
conformité, qualité et perspectives.

Le PDF produit **n'est pas versionné** — aucun binaire généré ne l'est dans ce
dépôt. Il est reconstruit à chaque exécution de la CI et publié en artefact du
workflow `ci`, sous le nom `fasoshield-presentation`.

## Régénérer

```bash
python docs/presentation/gen_assets.py   # figures matplotlib -> assets/
python docs/presentation/gen_pdf.py      # document reportlab
```

Dépendances de génération uniquement (elles ne font pas partie du paquet) :

```bash
pip install reportlab matplotlib
```

## Principes du document

Les chiffres cités proviennent du dépôt et sont recalculés à chaque génération
ou vérifiés à la main :

- la répartition du code est mesurée par `gen_assets.py` en parcourant les
  sources Python et Kotlin ;
- la répartition des tests correspond à
  `grep -c "^def test_" tests/test_*.py` ;
- la couverture est celle rapportée par `pytest --cov`.

Si le code évolue, relancer `gen_assets.py` avant `gen_pdf.py` pour que les
figures restent exactes.

> `_preview/` (rendus PNG des pages, utiles pour relire la mise en page) est
> ignoré par git.
