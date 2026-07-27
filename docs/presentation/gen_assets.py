"""Figures for the FasoShield presentation document.

Run from the repository root:

    python docs/presentation/gen_assets.py

Every figure is generated from the project's own facts (pipeline layers,
workflow states, module sizes, test counts) rather than from invented numbers.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

ASSETS = Path(__file__).resolve().parent / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

# Palette — matches the console's teal identity.
INK = "#0f172a"
MUTED = "#64748b"
BORDER = "#cbd5e1"
PRIMARY = "#0f766e"
PRIMARY_SOFT = "#ccfbf1"
ACCENT = "#b45309"
DANGER = "#b91c1c"
OK = "#15803d"
BG = "#ffffff"

plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": ["Segoe UI", "DejaVu Sans"],
        "figure.facecolor": BG,
        "axes.facecolor": BG,
        "savefig.facecolor": BG,
        "axes.edgecolor": BORDER,
        "text.color": INK,
        "axes.labelcolor": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
    }
)


def _save(fig, name: str) -> None:
    path = ASSETS / name
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    print(f"  {name}")


def _box(ax, x, y, w, h, text, face, edge, fontsize=9, textcolor=INK, weight="normal"):
    ax.add_patch(
        FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.02,rounding_size=0.06",
            facecolor=face, edgecolor=edge, linewidth=1.2,
        )
    )
    ax.text(
        x + w / 2, y + h / 2, text,
        ha="center", va="center", fontsize=fontsize, color=textcolor, weight=weight,
    )


def _arrow(ax, start, end, color=MUTED, style="-|>"):
    ax.add_patch(
        FancyArrowPatch(
            start, end, arrowstyle=style, mutation_scale=13,
            color=color, linewidth=1.3, shrinkA=2, shrinkB=2,
        )
    )


# -- 1. Architecture -------------------------------------------------------


def architecture() -> None:
    fig, ax = plt.subplots(figsize=(9.6, 5.0))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.6)
    ax.axis("off")

    _box(ax, 0.1, 3.9, 2.5, 1.2,
         "Agent Android\n(Kotlin, hors ligne)", PRIMARY_SOFT, PRIMARY, weight="bold")
    _box(ax, 0.1, 2.2, 2.5, 1.2,
         "Console SOC\n(analyste, RBAC)", PRIMARY_SOFT, PRIMARY, weight="bold")
    _box(ax, 0.1, 0.5, 2.5, 1.2,
         "CLI analyste\n(CERT national)", PRIMARY_SOFT, PRIMARY, weight="bold")

    _box(ax, 3.7, 1.4, 2.9, 3.7, "", "#f8fafc", PRIMARY)
    ax.text(5.15, 4.8, "API FasoShield", ha="center", fontsize=11,
            weight="bold", color=PRIMARY)
    for index, label in enumerate([
        "Moteur d'analyse 4 couches",
        "Réputation par empreinte",
        "Distribution delta",
        "Gouvernance des signatures",
        "Exports STIX / MISP",
        "File de scan différé",
    ]):
        ax.text(3.95, 4.35 - index * 0.44, f"· {label}", ha="left",
                fontsize=8.5, color=INK)

    _box(ax, 7.5, 3.6, 2.4, 1.1, "PostgreSQL\ncorpus + télémétrie", "#f8fafc", BORDER)
    _box(ax, 7.5, 2.1, 2.4, 1.1, "Quarantaine\n(objet ou disque)", "#f8fafc", BORDER)
    _box(ax, 7.5, 0.6, 2.4, 1.1, "CERT partenaires\nSTIX 2.1 / MISP", "#fff7ed", ACCENT)

    _arrow(ax, (2.6, 4.5), (3.7, 3.9))
    _arrow(ax, (2.6, 2.8), (3.7, 3.1))
    _arrow(ax, (2.6, 1.1), (3.7, 2.2))
    _arrow(ax, (6.6, 3.9), (7.5, 4.1))
    _arrow(ax, (6.6, 3.0), (7.5, 2.7))
    _arrow(ax, (6.6, 2.0), (7.5, 1.2), color=ACCENT)

    ax.text(3.15, 4.35, "HTTPS", fontsize=7.5, color=MUTED, rotation=-22)

    _save(fig, "architecture.png")


# -- 2. Scan pipeline ------------------------------------------------------


def pipeline() -> None:
    fig, ax = plt.subplots(figsize=(9.6, 3.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 3.4)
    ax.axis("off")

    layers = [
        ("1. Empreinte", "SHA-256 du fichier\net du certificat", "O(1)"),
        ("2. YARA", "fichier brut +\nclasses*.dex extraits", "ms"),
        ("3. Statique", "manifeste, permissions,\ncertificat (Androguard)", "100 ms"),
        ("4. Heuristiques", "usurpation, OTP, overlay,\ndropper, hygiène", "µs"),
    ]
    width, gap = 2.15, 0.35
    for index, (title, detail, cost) in enumerate(layers):
        x = 0.15 + index * (width + gap)
        _box(ax, x, 1.0, width, 1.5, "", "#f8fafc", PRIMARY)
        ax.text(x + width / 2, 2.22, title, ha="center", fontsize=9.5,
                weight="bold", color=PRIMARY)
        ax.text(x + width / 2, 1.62, detail, ha="center", fontsize=8, color=INK)
        ax.text(x + width / 2, 1.15, cost, ha="center", fontsize=7.5, color=MUTED)
        if index < len(layers) - 1:
            _arrow(ax, (x + width, 1.75), (x + width + gap, 1.75), color=PRIMARY)

    ax.text(5.0, 0.45,
            "Le pipeline aboutit toujours : une archive corrompue ou un fichier "
            "non-APK produit\nquand même un rapport — aucune entrée ne peut faire taire le moteur.",
            ha="center", fontsize=8, color=MUTED, style="italic")
    ax.text(5.0, 2.95, "Du moins coûteux au plus coûteux",
            ha="center", fontsize=8.5, color=MUTED)

    _save(fig, "pipeline.png")


# -- 3. Signature workflow -------------------------------------------------


def workflow() -> None:
    fig, ax = plt.subplots(figsize=(9.6, 3.2))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 3.0)
    ax.axis("off")

    _box(ax, 0.3, 1.5, 1.9, 0.85, "DRAFT\nbrouillon", "#f1f5f9", MUTED, weight="bold")
    _box(ax, 3.0, 1.5, 1.9, 0.85, "REVIEW\nen revue", "#fef3c7", ACCENT, weight="bold")
    _box(ax, 5.9, 2.05, 1.9, 0.85, "PUBLISHED\npubliée", "#dcfce7", OK, weight="bold")
    _box(ax, 5.9, 0.75, 1.9, 0.85, "REJECTED\nrejetée", "#fee2e2", DANGER, weight="bold")
    _box(ax, 8.4, 2.05, 1.4, 0.85, "Agents\n(sync delta)", PRIMARY_SOFT, PRIMARY)

    _arrow(ax, (2.2, 1.92), (3.0, 1.92), color=MUTED)
    _arrow(ax, (4.9, 2.1), (5.9, 2.4), color=OK)
    _arrow(ax, (4.9, 1.75), (5.9, 1.2), color=DANGER)
    _arrow(ax, (7.8, 2.47), (8.4, 2.47), color=PRIMARY)

    ax.text(2.6, 2.15, "submit", fontsize=7.5, color=MUTED, ha="center")
    ax.text(5.35, 2.45, "approve", fontsize=7.5, color=OK, ha="center")
    ax.text(5.35, 1.28, "reject", fontsize=7.5, color=DANGER, ha="center")

    ax.text(5.0, 0.28,
            "Règle des quatre yeux : l'auteur d'une proposition ne peut ni l'approuver "
            "ni la rejeter,\nmême administrateur. Chaque transition est écrite au journal d'audit.",
            ha="center", fontsize=8.5, color=INK, style="italic")

    _save(fig, "workflow.png")


# -- 4. Identity separation ------------------------------------------------


def identities() -> None:
    fig, ax = plt.subplots(figsize=(9.0, 3.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 3.6)
    ax.axis("off")

    _box(ax, 0.2, 0.35, 4.5, 2.75, "", "#f8fafc", PRIMARY)
    ax.text(2.45, 2.85, "Agents mobiles", ha="center", fontsize=11,
            weight="bold", color=PRIMARY)
    ax.text(2.45, 2.5, "clé d'API partagée", ha="center", fontsize=8.5, color=MUTED)
    for index, item in enumerate([
        "réputation par empreinte",
        "mises à jour de signatures",
        "envoi de télémétrie",
        "dépôt d'échantillon",
    ]):
        ax.text(0.55, 2.05 - index * 0.36, f"• {item}", ha="left",
                fontsize=8.5, color=OK)
    ax.text(0.55, 0.55, "aucun accès : console, statistiques, exports",
            ha="left", fontsize=8.5, color=DANGER)

    _box(ax, 5.3, 0.35, 4.5, 2.75, "", "#f8fafc", ACCENT)
    ax.text(7.55, 2.85, "Analystes", ha="center", fontsize=11,
            weight="bold", color=ACCENT)
    ax.text(7.55, 2.5, "compte nominatif, session ou SSO", ha="center",
            fontsize=8.5, color=MUTED)
    for index, item in enumerate([
        "viewer — lecture du tableau de bord",
        "analyst — proposer, revoir, publier",
        "admin — gérer les comptes",
    ]):
        ax.text(5.65, 2.05 - index * 0.36, f"· {item}", ha="left",
                fontsize=8.5, color=INK)
    ax.text(7.55, 0.75, "toute action est auditée", ha="center",
            fontsize=8.5, color=MUTED, style="italic")

    _save(fig, "identities.png")


# -- 5. Codebase composition ----------------------------------------------


def codebase() -> None:
    """Module sizes, measured from the repository."""
    root = Path(__file__).resolve().parents[2]

    groups = {
        "Moteur d'analyse": ["src/fasoshield/engine"],
        "API et console": ["src/fasoshield/api"],
        "Gouvernance et intel": [
            "src/fasoshield/governance.py",
            "src/fasoshield/intel.py",
            "src/fasoshield/accounts.py",
            "src/fasoshield/security.py",
        ],
        "File et stockage": ["src/fasoshield/jobs.py", "src/fasoshield/storage.py"],
        "CLI": ["src/fasoshield/cli.py"],
        "Agent Android": ["android/app/src/main"],
        "Tests": ["tests", "android/app/src/test"],
    }

    def count(patterns: list[str]) -> int:
        total = 0
        for pattern in patterns:
            target = root / pattern
            if target.is_file():
                total += len(target.read_text(encoding="utf-8").splitlines())
            elif target.is_dir():
                for suffix in ("*.py", "*.kt"):
                    for path in target.rglob(suffix):
                        total += len(path.read_text(encoding="utf-8").splitlines())
        return total

    labels = list(groups)
    values = [count(paths) for paths in groups.values()]

    fig, ax = plt.subplots(figsize=(8.2, 3.6))
    bars = ax.barh(labels[::-1], values[::-1], color=PRIMARY, height=0.62)
    bars[-1].set_color(ACCENT)  # highlight the engine
    for bar, value in zip(bars, values[::-1], strict=False):
        ax.text(bar.get_width() + max(values) * 0.015, bar.get_y() + bar.get_height() / 2,
                f"{value}", va="center", fontsize=8.5, color=MUTED)
    ax.set_xlabel("lignes de code", fontsize=9)
    ax.set_xlim(0, max(values) * 1.14)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0, labelsize=9)
    ax.grid(axis="x", color=BORDER, linewidth=0.6, alpha=0.6)
    ax.set_axisbelow(True)

    _save(fig, "codebase.png")
    return dict(zip(labels, values, strict=False))


# -- 6. Threat landscape ---------------------------------------------------


def threats() -> None:
    fig, ax = plt.subplots(figsize=(8.6, 3.5))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 3.4)
    ax.axis("off")

    items = [
        ("Fausses applications\nmobile money",
         "clones d'Orange Money, Moov,\nWave diffusés hors store",
         "certificat + registre officiel"),
        ("Vol d'OTP par\ninterception SMS",
         "RECEIVE_SMS + INTERNET pour\ncapter les codes de validation",
         "combinaison de permissions"),
        ("Trojans bancaires\nà superposition",
         "faux écran de saisie du PIN\nau-dessus de l'app légitime",
         "SYSTEM_ALERT_WINDOW"),
        ("Droppers et\nsmishing en français",
         "charge secondaire, SMS usurpant\nles opérateurs",
         "règles YARA nationales"),
    ]
    width, gap = 2.20, 0.30
    for index, (title, detail, control) in enumerate(items):
        x = 0.15 + index * (width + gap)
        _box(ax, x, 0.6, width, 2.4, "", "#fff7ed", ACCENT)
        ax.text(x + width / 2, 2.62, title, ha="center", fontsize=9,
                weight="bold", color=ACCENT)
        ax.text(x + width / 2, 1.85, detail, ha="center", fontsize=7.8, color=INK)
        ax.text(x + width / 2, 0.95, f"→ {control}", ha="center", fontsize=7.5,
                color=PRIMARY, weight="bold")

    ax.text(5.0, 0.18,
            "Le paiement mobile est l'infrastructure financière dominante : "
            "compromettre l'application, c'est compromettre le compte.",
            ha="center", fontsize=8, color=MUTED, style="italic")

    _save(fig, "threats.png")


# -- 7. Coverage and quality ----------------------------------------------


def quality() -> None:
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.0))

    # Coverage donut.
    ax = axes[0]
    covered, missed = 94, 6
    ax.pie(
        [covered, missed],
        colors=[PRIMARY, "#e2e8f0"],
        startangle=90,
        counterclock=False,
        wedgeprops={"width": 0.34, "edgecolor": BG, "linewidth": 2},
    )
    ax.text(0, 0.06, "94 %", ha="center", va="center", fontsize=20,
            weight="bold", color=PRIMARY)
    ax.text(0, -0.28, "couverture", ha="center", va="center", fontsize=9, color=MUTED)
    ax.set_title("Tests", fontsize=10, color=INK, pad=10)

    # Test distribution.
    ax = axes[1]
    # Measured with: grep -c "^def test_" tests/test_*.py
    suites = {
        "auth / RBAC": 28,
        "moteur": 26,  # heuristiques, scanner, hashdb, YARA
        "CLI": 23,
        "gouvernance": 18,
        "intel": 15,
        "file de scan": 15,
        "durcissement": 10,
        "API": 8,
        "console / stats": 7,
    }
    labels = list(suites)
    values = list(suites.values())
    ax.barh(labels[::-1], values[::-1], color=PRIMARY, height=0.6)
    for index, value in enumerate(values[::-1]):
        ax.text(value + 0.8, index, str(value), va="center", fontsize=8, color=MUTED)
    ax.set_xlim(0, max(values) * 1.2)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0, labelsize=8.5)
    ax.tick_params(axis="x", labelsize=8)
    ax.grid(axis="x", color=BORDER, linewidth=0.6, alpha=0.6)
    ax.set_axisbelow(True)
    ax.set_title("150 tests par domaine", fontsize=10, color=INK, pad=10)

    fig.tight_layout()
    _save(fig, "quality.png")


# -- 8. Roadmap ------------------------------------------------------------


def roadmap() -> None:
    fig, ax = plt.subplots(figsize=(9.4, 2.9))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 2.7)
    ax.axis("off")

    phases = [
        ("Phase 1", "Moteur d'analyse", True),
        ("Phase 2", "API plateforme", True),
        ("Phase 3", "Agent Android", True),
        ("Phase 4", "Console et\ngouvernance", True),
        ("Phase 5", "Durcissement et\ndéploiement", True),
    ]
    width, gap = 1.72, 0.22
    for index, (phase, title, done) in enumerate(phases):
        x = 0.25 + index * (width + gap)
        face = "#dcfce7" if done else "#f1f5f9"
        edge = OK if done else BORDER
        _box(ax, x, 0.85, width, 1.15, "", face, edge)
        ax.text(x + width / 2, 1.68, phase, ha="center", fontsize=9,
                weight="bold", color=OK if done else MUTED)
        ax.text(x + width / 2, 1.24, title, ha="center", fontsize=7.6,
                color=INK, linespacing=1.4)
        ax.text(x + width / 2, 0.98, "livré" if done else "à venir",
                ha="center", fontsize=7.5, color=OK if done else MUTED)
        if index < len(phases) - 1:
            _arrow(ax, (x + width, 1.42), (x + width + gap, 1.42), color=BORDER)

    ax.text(5.0, 0.42,
            "Reste ouvert : l'audit de sécurité externe — travail de tiers par nature — "
            "et la remise\nde la clé de signature nationale, préalable à la publication publique.",
            ha="center", fontsize=8, color=MUTED, style="italic")

    _save(fig, "roadmap.png")


if __name__ == "__main__":
    print("Génération des visuels :")
    architecture()
    pipeline()
    workflow()
    identities()
    sizes = codebase()
    threats()
    quality()
    roadmap()
    print("\nLignes de code mesurées :")
    for name, value in sizes.items():
        print(f"  {name:24} {value:>6}")
