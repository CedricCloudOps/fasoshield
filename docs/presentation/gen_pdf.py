"""FasoShield — presentation document (PDF).

Run from the repository root, after gen_assets.py:

    python docs/presentation/gen_assets.py
    python docs/presentation/gen_pdf.py

Produces docs/presentation/FasoShield_Presentation.pdf.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
OUTPUT = HERE / "FasoShield_Presentation.pdf"

AUTHOR = "DJIGUIMDE Cédric Severin"
SUBTITLE = "Plateforme nationale de protection contre les menaces mobiles"

# Palette, aligned with the SOC console.
INK = colors.HexColor("#0f172a")
MUTED = colors.HexColor("#64748b")
PRIMARY = colors.HexColor("#0f766e")
PRIMARY_SOFT = colors.HexColor("#ccfbf1")
ACCENT = colors.HexColor("#b45309")
ACCENT_SOFT = colors.HexColor("#fff7ed")
DANGER = colors.HexColor("#b91c1c")
OK = colors.HexColor("#15803d")
BORDER = colors.HexColor("#cbd5e1")
PANEL = colors.HexColor("#f8fafc")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


# -- styles ----------------------------------------------------------------


def build_styles() -> dict:
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "title", parent=base["Title"], fontName="Helvetica-Bold",
        fontSize=30, leading=35, textColor=colors.white, alignment=TA_CENTER,
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle", parent=base["Normal"], fontName="Helvetica",
        fontSize=13, leading=18, textColor=colors.HexColor("#a7f3d0"),
        alignment=TA_CENTER,
    )
    styles["cover_meta"] = ParagraphStyle(
        "cover_meta", parent=base["Normal"], fontName="Helvetica",
        fontSize=10, leading=15, textColor=colors.HexColor("#d1fae5"),
        alignment=TA_CENTER,
    )
    styles["h1"] = ParagraphStyle(
        "h1", parent=base["Heading1"], fontName="Helvetica-Bold",
        fontSize=17, leading=21, textColor=PRIMARY, spaceBefore=2, spaceAfter=8,
    )
    styles["h2"] = ParagraphStyle(
        "h2", parent=base["Heading2"], fontName="Helvetica-Bold",
        fontSize=11.5, leading=15, textColor=INK, spaceBefore=10, spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "body", parent=base["BodyText"], fontName="Helvetica",
        fontSize=9.5, leading=14, textColor=INK, alignment=TA_JUSTIFY,
        spaceAfter=6,
    )
    styles["bullet"] = ParagraphStyle(
        "bullet", parent=styles["body"], leftIndent=10, bulletIndent=2,
        spaceAfter=3, alignment=TA_JUSTIFY,
    )
    styles["caption"] = ParagraphStyle(
        "caption", parent=base["Normal"], fontName="Helvetica-Oblique",
        fontSize=8, leading=11, textColor=MUTED, alignment=TA_CENTER,
        spaceBefore=3, spaceAfter=8,
    )
    styles["cell"] = ParagraphStyle(
        "cell", parent=base["Normal"], fontName="Helvetica",
        fontSize=8.2, leading=11, textColor=INK,
    )
    styles["cell_head"] = ParagraphStyle(
        "cell_head", parent=styles["cell"], fontName="Helvetica-Bold",
        textColor=colors.white,
    )
    styles["code"] = ParagraphStyle(
        "code", parent=base["Normal"], fontName="Courier",
        fontSize=8, leading=11.5, textColor=INK,
        backColor=PANEL, borderColor=BORDER, borderWidth=0.6,
        borderPadding=6, leftIndent=2, rightIndent=2, spaceAfter=8,
    )
    styles["callout"] = ParagraphStyle(
        "callout", parent=styles["body"], fontSize=9.2, leading=13.5,
        textColor=INK, alignment=TA_JUSTIFY,
    )
    styles["toc"] = ParagraphStyle(
        "toc", parent=base["Normal"], fontName="Helvetica",
        fontSize=10, leading=17, textColor=INK,
    )
    return styles


S = build_styles()


# -- page furniture --------------------------------------------------------


def cover_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#0b3b38"))
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

    # Shield mark.
    cx, cy = PAGE_W / 2, PAGE_H - 78 * mm
    canvas.setStrokeColor(colors.HexColor("#2dd4bf"))
    canvas.setLineWidth(2.2)
    path = canvas.beginPath()
    w, h = 17 * mm, 22 * mm
    path.moveTo(cx - w, cy + h * 0.42)
    path.lineTo(cx - w, cy - h * 0.10)
    path.curveTo(cx - w, cy - h * 0.62, cx - w * 0.35, cy - h * 0.86, cx, cy - h)
    path.curveTo(cx + w * 0.35, cy - h * 0.86, cx + w, cy - h * 0.62, cx + w, cy - h * 0.10)
    path.lineTo(cx + w, cy + h * 0.42)
    path.close()
    canvas.drawPath(path, stroke=1, fill=0)
    canvas.setFillColor(colors.HexColor("#2dd4bf"))
    canvas.setFont("Helvetica-Bold", 20)
    canvas.drawCentredString(cx, cy - 4 * mm, "FS")

    canvas.setStrokeColor(colors.HexColor("#2dd4bf"))
    canvas.setLineWidth(1)
    canvas.line(MARGIN + 35 * mm, 62 * mm, PAGE_W - MARGIN - 35 * mm, 62 * mm)
    canvas.restoreState()


def content_page(canvas, doc):
    canvas.saveState()
    # Header rule and running title.
    canvas.setFillColor(PRIMARY)
    canvas.rect(0, PAGE_H - 13 * mm, PAGE_W, 3.2, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, PAGE_H - 10.5 * mm, "FasoShield")
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 10.5 * mm, SUBTITLE)

    # Footer.
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(MARGIN, 11 * mm, AUTHOR)
    canvas.drawRightString(PAGE_W - MARGIN, 11 * mm, str(canvas.getPageNumber()))
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
    canvas.restoreState()


# -- content helpers -------------------------------------------------------


def h1(text: str) -> Paragraph:
    return Paragraph(text, S["h1"])


def h2(text: str) -> Paragraph:
    return Paragraph(text, S["h2"])


def p(text: str) -> Paragraph:
    return Paragraph(text, S["body"])


def bullets(items: list[str]) -> list:
    return [Paragraph(item, S["bullet"], bulletText="•") for item in items]


def code(text: str) -> Paragraph:
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(escaped.replace("\n", "<br/>"), S["code"])


def figure(name: str, caption: str, width: float = CONTENT_W) -> list:
    path = ASSETS / name
    image = Image(str(path))
    ratio = image.imageHeight / image.imageWidth
    image.drawWidth = width
    image.drawHeight = width * ratio
    return [Spacer(1, 3), KeepTogether([image, Paragraph(caption, S["caption"])])]


def table(rows: list[list[str]], widths: list[float], header: bool = True) -> Table:
    data = []
    for index, row in enumerate(rows):
        style = S["cell_head"] if (header and index == 0) else S["cell"]
        data.append([Paragraph(str(cell), style) for cell in row])

    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        commands += [
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]),
        ]
    else:
        commands.append(("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, PANEL]))

    result = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    result.setStyle(TableStyle(commands))
    return result


def callout(title: str, text: str, tone: str = "primary") -> Table:
    face, edge = {
        "primary": (PRIMARY_SOFT, PRIMARY),
        "accent": (ACCENT_SOFT, ACCENT),
        "neutral": (PANEL, BORDER),
    }[tone]
    heading = ParagraphStyle(
        "callout_head", parent=S["h2"], spaceBefore=0, spaceAfter=3,
        textColor=edge, fontSize=10,
    )
    inner = [[Paragraph(title, heading)], [Paragraph(text, S["callout"])]]
    result = Table(inner, colWidths=[CONTENT_W - 10])
    result.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), face),
            ("BOX", (0, 0), (-1, -1), 0.9, edge),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, 0), 7),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
        ])
    )
    return KeepTogether(result)


def kpi_row(items: list[tuple[str, str]]) -> Table:
    number = ParagraphStyle(
        "kpi_n", parent=S["body"], fontName="Helvetica-Bold", fontSize=17,
        leading=20, textColor=PRIMARY, alignment=TA_CENTER, spaceAfter=0,
    )
    label = ParagraphStyle(
        "kpi_l", parent=S["body"], fontSize=7.6, leading=10, textColor=MUTED,
        alignment=TA_CENTER, spaceAfter=0,
    )
    data = [
        [Paragraph(value, number) for value, _ in items],
        [Paragraph(text, label) for _, text in items],
    ]
    width = CONTENT_W / len(items)
    result = Table(data, colWidths=[width] * len(items))
    result.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
            ("TOPPADDING", (0, 1), (-1, 1), 0),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    return result


# -- document --------------------------------------------------------------


def build_story() -> list:
    story: list = []

    # ---------------- Cover ----------------
    story.append(Spacer(1, 92 * mm))
    story.append(Paragraph("FasoShield", S["title"]))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(SUBTITLE, S["subtitle"]))
    story.append(Spacer(1, 40 * mm))
    story.append(
        Paragraph(
            "Moteur d'analyse d'APK · API de réputation · Gouvernance des signatures<br/>"
            "Agent Android souverain · Partage de renseignement avec les CERT",
            S["cover_meta"],
        )
    )
    story.append(Spacer(1, 22 * mm))
    story.append(
        Paragraph(
            f"{AUTHOR}<br/>Dossier de présentation — {date.today().strftime('%d/%m/%Y')}",
            S["cover_meta"],
        )
    )
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # ---------------- Synthèse ----------------
    story.append(h1("1. Synthèse"))
    story.append(
        p(
            "FasoShield est une plateforme nationale de lutte contre les logiciels "
            "malveillants visant les téléphones mobiles, et plus précisément les comptes "
            "de monnaie électronique. Elle réunit un moteur d'analyse d'applications "
            "Android, une API de réputation interrogée par un agent mobile, une console "
            "d'analyse pour le CERT national, un circuit de validation des signatures et "
            "un canal de partage avec les CERT partenaires."
        )
    )
    story.append(
        p(
            "Le projet répond à un angle mort des antivirus commerciaux : leurs "
            "signatures visent les menaces mondiales, ils ne disposent d'aucun registre "
            "des applications financières locales, ils n'ont pas de règles sur les leurres "
            "rédigés en français, et leur télémétrie quitte le territoire. FasoShield "
            "renverse ces quatre points."
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        kpi_row([
            ("4", "couches d'analyse"),
            ("150", "tests automatisés"),
            ("94 %", "couverture de code"),
            ("5/5", "phases livrées"),
            ("2", "formats CERT"),
        ])
    )
    story.append(Spacer(1, 10))
    story.append(
        callout(
            "Le choix structurant",
            "Aucun indicateur n'atteint les téléphones sans avoir été validé par deux "
            "analystes distincts. Un faux positif sur une application de monnaie "
            "électronique couperait des milliers d'usagers de leurs fonds : c'est un "
            "risque plus grave qu'une détection manquée, et l'architecture est bâtie "
            "autour de ce constat.",
        )
    )

    story.append(h2("Ce que contient ce document"))
    for line in [
        "2. Le problème — le paysage de menaces ouest-africain",
        "3. L'architecture d'ensemble",
        "4. Le moteur d'analyse en quatre couches",
        "5. L'agent Android et le fonctionnement hors ligne",
        "6. La console SOC et la séparation des identités",
        "7. La gouvernance des signatures",
        "8. Le partage de renseignement avec les CERT",
        "9. Exploitation, montée en charge et déploiement",
        "10. Sécurité et conformité",
        "11. Qualité logicielle",
        "12. Bilan et perspectives",
    ]:
        story.append(Paragraph(line, S["toc"]))

    story.append(PageBreak())

    # ---------------- Problème ----------------
    story.append(h1("2. Le problème"))
    story.append(
        p(
            "En Afrique de l'Ouest, le paiement mobile n'est pas un service annexe : "
            "c'est l'infrastructure financière dominante. Pour une grande partie de la "
            "population, le compte de monnaie électronique <i>est</i> le compte bancaire. "
            "Compromettre l'application, c'est donc compromettre directement l'épargne "
            "de la personne — sans intermédiaire, sans plafond de carte, sans procédure "
            "de contestation comparable à celle d'une banque."
        )
    )
    story.extend(
        figure("threats.png",
               "Les quatre vecteurs dominants et le contrôle qui leur répond.")
    )
    story.append(
        p(
            "Ces campagnes partagent une caractéristique décisive : elles se diffusent "
            "<b>hors des magasins officiels</b>, par liens WhatsApp ou Telegram et par "
            "boutiques alternatives. C'est ce qui rend exploitable un signal que les "
            "antivirus génériques utilisent mal — la provenance de l'application."
        )
    )
    story.append(
        callout(
            "Pourquoi les produits commerciaux couvrent mal ce terrain",
            "Leurs bases de signatures sont alimentées par la télémétrie mondiale, où "
            "une campagne visant Orange Money au Burkina pèse statistiquement peu. Ils "
            "n'ont pas de registre des certificats de signature des applications "
            "financières locales, donc ils ne savent pas distinguer la vraie application "
            "de son clone. Et leurs règles de détection de hameçonnage sont écrites pour "
            "l'anglais.",
            tone="accent",
        )
    )

    story.append(PageBreak())

    # ---------------- Architecture ----------------
    story.append(h1("3. Architecture d'ensemble"))
    story.append(
        p(
            "Trois clients, une API, un stockage national. L'agent mobile fonctionne "
            "hors ligne et n'interroge la plateforme que pour la réputation d'une "
            "empreinte et la synchronisation de ses signatures. La console sert le CERT. "
            "La ligne de commande couvre l'exploitation serveur, là où aucun navigateur "
            "n'est disponible."
        )
    )
    story.extend(figure("architecture.png", "Vue d'ensemble des composants et des flux."))

    story.append(h2("Principes retenus"))
    story.extend(
        bullets([
            "<b>Souveraineté</b> — aucune dépendance à un service en nuage étranger. Le "
            "stockage objet est optionnel : la plateforme se déploie sur une "
            "infrastructure isolée, disque local compris.",
            "<b>Minimisation</b> — les champs identifiants n'existent pas dans le schéma "
            "de base de données. Ils ne peuvent donc pas être activés par un simple "
            "changement de configuration.",
            "<b>Dégradation maîtrisée</b> — l'agent protège l'appareil sans réseau ; "
            "l'analyse aboutit toujours à un rapport, même sur une archive corrompue.",
            "<b>Coût d'exploitation faible</b> — pas de courtier de messages, pas de "
            "cluster : la file de scan différé s'appuie sur la base de données.",
        ])
    )

    story.append(h2("Choix techniques"))
    story.append(
        table(
            [
                ["Composant", "Technologie", "Motif"],
                ["API", "FastAPI, SQLAlchemy 2", "Contrats typés, documentation OpenAPI générée, "
                 "portabilité SQLite → PostgreSQL"],
                ["Analyse statique", "Androguard", "Lecture du manifeste binaire et du certificat "
                 "de signature sans exécuter l'application"],
                ["Détection de motifs", "YARA", "Format standard du métier ; les règles "
                 "nationales sont lisibles et auditables par un tiers"],
                ["Agent mobile", "Kotlin, Room, WorkManager",
                 "Base locale, travaux en arrière-plan résistants au redémarrage"],
                ["Authentification", "scrypt, sessions serveur", "Sans dépendance externe ; jetons "
                 "révocables, stockés hachés"],
            ],
            widths=[CONTENT_W * 0.20, CONTENT_W * 0.26, CONTENT_W * 0.54],
        )
    )

    story.append(PageBreak())

    # ---------------- Moteur ----------------
    story.append(h1("4. Le moteur d'analyse"))
    story.append(
        p(
            "Le pipeline enchaîne quatre couches, ordonnées du moins coûteux au plus "
            "coûteux. Chaque couche ajoute ses constats à un rapport commun ; le verdict "
            "final agrège les sévérités."
        )
    )
    story.extend(figure("pipeline.png", "Les quatre couches du moteur d'analyse."))

    story.append(h2("Deux détails qui font la différence"))
    story.append(
        p(
            "<b>Le DEX est compressé dans l'APK.</b> Passer YARA sur le fichier brut ne "
            "voit rien du bytecode : les chaînes caractéristiques sont invisibles tant "
            "que <font face='Courier' size='8'>classes.dex</font> n'a pas été extrait. "
            "Le moteur extrait donc chaque entrée DEX et la scanne en mémoire, avec un "
            "plafond de 64 Mio et dix entrées au maximum pour borner le coût d'une "
            "archive hostile."
        )
    )
    story.append(
        p(
            "<b>Le certificat de signature convainc mieux que l'empreinte du fichier.</b> "
            "Un attaquant regénère son APK à volonté — l'empreinte change à chaque "
            "variante. La clé de signature, elle, est réutilisée sur toute une famille. "
            "La blocklist accepte donc les deux granularités, et un indicateur de "
            "certificat condamne les repacks que le moteur n'a jamais vus."
        )
    )

    story.append(h2("Couche heuristique"))
    story.append(
        table(
            [
                ["Règle", "Signal", "Sévérité"],
                ["heur.cert_mismatch", "Paquet officiel signé par une clé inconnue "
                 "— clone repackagé", "CRITIQUE"],
                ["heur.package_lookalike", "Nom de paquet très proche d'un paquet officiel",
                 "ÉLEVÉE"],
                ["heur.brand_in_label", "Marque financière dans le libellé d'un paquet "
                 "non enregistré", "ÉLEVÉE"],
                ["heur.sms_exfiltration", "Lecture des SMS entrants + accès réseau "
                 "— vol d'OTP", "ÉLEVÉE"],
                ["heur.spyware_combo", "Micro + réseau + localisation ou contacts", "ÉLEVÉE"],
                ["heur.overlay", "Superposition d'écran — faux écran de saisie du PIN",
                 "MOYENNE"],
                ["heur.dropper", "Peut installer d'autres paquets", "MOYENNE"],
                ["heur.legacy_target_sdk", "Cible un SDK antérieur aux permissions à "
                 "l'exécution", "MOYENNE"],
            ],
            widths=[CONTENT_W * 0.26, CONTENT_W * 0.58, CONTENT_W * 0.16],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        callout(
            "Un verdict qui s'explique",
            "Le rapport ne renvoie pas un score opaque : chaque constat porte son "
            "identifiant de règle, sa sévérité, sa description et la preuve qui l'a "
            "déclenché. Un analyste peut contester une détection ligne par ligne — "
            "condition nécessaire pour qu'une publication d'indicateur soit revue "
            "sérieusement par un second analyste.",
            tone="neutral",
        )
    )

    story.append(PageBreak())

    # ---------------- Agent ----------------
    story.append(h1("5. L'agent Android"))
    story.append(
        p(
            "L'agent analyse les applications installées <b>sur l'appareil</b> et "
            "n'envoie jamais d'APK sur le réseau. Il lit ce que "
            "<font face='Courier' size='8'>PackageManager</font> lui fournit — "
            "permissions, certificat, source d'installation, SDK cible — et applique "
            "les mêmes règles que le moteur serveur, avec les mêmes identifiants et les "
            "mêmes sévérités, pour que verdict local et verdict plateforme restent "
            "cohérents."
        )
    )

    story.append(h2("Fonctionnement hors ligne"))
    story.extend(
        bullets([
            "Base de signatures locale (Room), synchronisée en <b>delta</b> : l'agent ne "
            "télécharge que ce qui a été publié depuis sa dernière version.",
            "Détection des nouvelles installations par <font face='Courier' size='8'>"
            "PACKAGE_ADDED</font>, scan délégué à WorkManager.",
            "Scan périodique quotidien, ré-armé après redémarrage.",
            "Alerte à l'utilisateur avec le détail des raisons et la marche à suivre — "
            "l'agent <b>ne désinstalle jamais</b> lui-même.",
        ])
    )

    story.append(h2("La provenance comme filtre"))
    story.append(
        p(
            "C'est le raffinement que le serveur ne peut pas faire. L'appareil sait si "
            "une application est préinstallée ou vient d'un magasin officiel ; le serveur, "
            "qui ne voit qu'un fichier, l'ignore. Une application de messagerie installée "
            "depuis le Play Store lit légitimement les SMS pour remplir les codes de "
            "validation, et enregistre légitimement l'audio. La signaler noierait les "
            "vraies détections sous le bruit."
        )
    )
    story.append(
        p(
            "L'agent conditionne donc les heuristiques de permissions et d'hygiène à une "
            "provenance non fiable. Les contrôles d'usurpation et la blocklist, eux, "
            "s'appliquent toujours : un clone repackagé est malveillant quelle que soit "
            "sa source. Le nom du magasin installateur ne peut pas être falsifié par "
            "l'application installée, ce qui en fait un point d'ancrage solide."
        )
    )
    story.append(
        callout(
            "Une correction issue de la mise au point sur appareil réel",
            "Samsung Update Center déplace les applications système mises à jour vers "
            "<font face='Courier' size='8'>/data/app</font> et leur retire leurs "
            "indicateurs système. Sans traitement particulier, des applications "
            "constructeur parfaitement légitimes ressortaient comme installées hors "
            "magasin. L'installateur est reconnu comme source de confiance, et la "
            "détection d'origine système regarde aussi la partition d'installation.",
            tone="accent",
        )
    )

    story.append(PageBreak())

    # ---------------- Console ----------------
    story.append(h1("6. Console SOC et séparation des identités"))
    story.append(
        p(
            "La console donne au CERT la vue nationale : détections de terrain, "
            "répartition régionale, chronologie sur quatorze jours, menaces les plus "
            "fréquentes, file des signatures en attente de revue et journal d'audit."
        )
    )
    story.extend(
        figure("identities.png",
               "Deux systèmes d'authentification, deux portées disjointes.")
    )
    story.append(
        p(
            "La distinction n'est pas cosmétique. Une clé d'agent est distribuée avec "
            "l'application : elle vit sur des milliers de téléphones, dont certains "
            "seront perdus, revendus ou compromis. La traiter comme un secret sérieux "
            "serait une fiction. Elle n'ouvre donc que les points d'entrée dont un "
            "téléphone a besoin — et ni la console, ni les statistiques, ni les exports."
        )
    )

    story.append(h2("Identité analyste"))
    story.extend(
        bullets([
            "Mot de passe haché en <b>scrypt</b> (N = 2<super>16</super>, r = 8, "
            "soit 64 Mio de mémoire par calcul) : coûteux à casser sur GPU.",
            "par calcul) : coûteux à casser sur GPU.",
            "Session opaque stockée <b>uniquement sous forme d'empreinte SHA-256</b> — "
            "une copie de la base ne peut pas être rejouée comme session valide.",
            "Cookie <font face='Courier' size='8'>HttpOnly</font>, "
            "<font face='Courier' size='8'>SameSite=Lax</font>, "
            "<font face='Courier' size='8'>Secure</font>.",
            "Rôles <b>viewer</b> &lt; <b>analyst</b> &lt; <b>admin</b>. Un changement de "
            "mot de passe ou une désactivation révoque immédiatement les sessions.",
            "Réponse de connexion uniforme : mot de passe faux, compte inconnu et compte "
            "désactivé sont indiscernables, pour ne pas énumérer les opérateurs.",
            "Mode SSO par en-tête pour un déploiement derrière une passerelle OIDC, "
            "conditionné à l'isolement réseau de l'API.",
        ])
    )
    story.append(
        callout(
            "Interface sans dépendance externe",
            "La console n'utilise aucun CDN ni framework distant. Cela permet une "
            "politique de sécurité de contenu réellement stricte — "
            "<font face='Courier' size='8'>default-src 'none'</font> — avec un nonce "
            "régénéré à chaque réponse pour le script et la feuille de style embarqués. "
            "C'est aussi ce qui rend la console utilisable sur un réseau sans accès "
            "Internet sortant.",
            tone="neutral",
        )
    )

    story.append(PageBreak())

    # ---------------- Gouvernance ----------------
    story.append(h1("7. Gouvernance des signatures"))
    story.append(
        p(
            "C'est le cœur institutionnel du projet. Publier un indicateur revient à "
            "demander à des milliers d'appareils de considérer une application comme "
            "malveillante. Cette décision ne peut pas appartenir à une seule personne."
        )
    )
    story.extend(figure("workflow.png", "Le circuit de validation d'un indicateur."))

    story.append(
        table(
            [
                ["Contrôle", "Effet"],
                ["Aucune écriture directe", "La blocklist n'est jamais modifiée hors du "
                 "circuit — ni par l'API, ni par la ligne de commande"],
                ["Justification obligatoire", "Une proposition sans éléments de preuve "
                 "circonstanciés est refusée à la création"],
                ["Règle des quatre yeux", "L'auteur ne peut ni approuver ni rejeter sa "
                 "propre proposition, même administrateur"],
                ["Motif de rejet exigé", "Un refus sans raison est impossible : la "
                 "décision reste explicable"],
                ["Journal d'audit", "Proposition, soumission, publication et rejet sont "
                 "consignés avec acteur, cible et adresse IP"],
                ["Réversibilité", "L'historique complet permet de retrouver qui a publié "
                 "quoi, sur quelle base et quand"],
            ],
            widths=[CONTENT_W * 0.28, CONTENT_W * 0.72],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        p(
            "Une fois approuvé, l'indicateur entre dans la base de distribution et "
            "atteint les agents à leur synchronisation delta suivante. Les indicateurs "
            "de certificat sont stockés de manière à rester interrogeables par "
            "certificat, ce qui est la seule information dont dispose l'agent sans "
            "calculer l'empreinte de chaque APK installé."
        )
    )
    story.append(
        code(
            "$ fasoshield proposal list --status REVIEW\n"
            "#12   REVIEW   sha256   9f3c1a77b2e4d015…   "
            "Trojan.FakeOM   by alice / reviewed -\n"
            "\n"
            "$ fasoshield proposal show 12\n"
            "status        : REVIEW\n"
            "indicator     : sha256 9f3c1a77b2e4d015…\n"
            "proposed by   : alice on 2026-07-27 09:14:22+00:00\n"
            "justification :\n"
            "Clone d'Orange Money diffusé par WhatsApp : capture le PIN saisi\n"
            "et l'exfiltre vers un serveur de commande."
        )
    )

    story.append(PageBreak())

    # ---------------- Intel ----------------
    story.append(h1("8. Partage avec les CERT partenaires"))
    story.append(
        p(
            "Les indicateurs publiés sont exportables dans les deux formats que les "
            "communautés CERT consomment réellement : <b>STIX 2.1</b>, la norme OASIS, "
            "et l'<b>événement MISP</b>, format des instances déployées dans les "
            "communautés africaines et européennes."
        )
    )
    story.extend(
        bullets([
            "Les identifiants d'objets sont dérivés de l'indicateur lui-même. Réexporter "
            "le même IOC met donc à jour l'objet chez le partenaire au lieu d'en créer un "
            "doublon — la différence entre un flux exploitable et un flux qui pollue.",
            "Un indicateur de certificat est exporté comme objet "
            "<font face='Courier' size='8'>x509-certificate</font>, pas comme empreinte "
            "de fichier : envoyer l'un pour l'autre enverrait le partenaire chercher un "
            "échantillon qui n'existe pas.",
            "Marquage TLP appliqué au bundle et à l'événement ; l'événement MISP est "
            "livré <b>non publié</b>, le CERT destinataire décide de sa diffusion.",
            "<b>Aucune donnée de télémétrie n'est exportée</b> : seules des empreintes de "
            "fichiers et de certificats franchissent la frontière.",
            "Chaque export est écrit au journal d'audit avec son auteur et son volume.",
        ])
    )
    story.append(
        code(
            "$ fasoshield intel stix -o bundle.json\n"
            "412 indicators written to bundle.json\n"
            "\n"
            "$ fasoshield intel misp --since 20260701000000 -o event.json\n"
            "37 indicators written to event.json"
        )
    )

    story.append(h1("9. Exploitation et déploiement"))
    story.append(
        p(
            "L'API est sans état et se réplique derrière un répartiteur de charge. La "
            "difficulté classique — analyser un gros APK sans bloquer une connexion HTTP "
            "— est traitée par une file de scan différé."
        )
    )
    story.append(
        p(
            "Au-delà d'un seuil de taille, le dépôt est mis en attente et le client "
            "reçoit un identifiant de travail qu'il interroge. La table des travaux "
            "<i>est</i> la file : un worker prend un travail par mise à jour "
            "conditionnelle, que la base sérialise pour nous. Plusieurs instances d'API, "
            "ou des workers dédiés, partagent donc la charge <b>sans courtier de "
            "messages</b> — un composant de moins à exploiter dans une infrastructure "
            "qui doit rester simple à maintenir."
        )
    )
    story.append(
        table(
            [
                ["Déploiement", "Base", "Quarantaine", "Workers"],
                ["Développement", "SQLite", "disque local", "intégré à l'API"],
                ["Serveur unique", "PostgreSQL", "disque local", "intégré à l'API"],
                ["Réparti", "PostgreSQL", "stockage objet <i>(obligatoire)</i>",
                 "conteneurs dédiés"],
            ],
            widths=[CONTENT_W * 0.24, CONTENT_W * 0.20, CONTENT_W * 0.34, CONTENT_W * 0.22],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        callout(
            "Distribution de l'agent",
            "La configuration de signature release lit un keystore externe au dépôt, "
            "jamais versionné. Si aucun keystore n'est fourni, le build produit un "
            "artefact <b>non signé</b> plutôt que de retomber silencieusement sur la clé "
            "de debug : une absence de signature se remarque immédiatement, un artefact "
            "signé en debug passerait inaperçu jusqu'aux utilisateurs. L'empreinte du "
            "certificat officiel doit être publiée pour que chacun puisse vérifier qu'il "
            "installe le vrai agent.",
            tone="accent",
        )
    )

    story.append(PageBreak())

    # ---------------- Sécurité et conformité ----------------
    story.append(h1("10. Sécurité et conformité"))
    story.append(
        p(
            "Le modèle de menaces retient cinq profils d'attaquants : l'opérateur de "
            "fraude qui cherche à ne pas être détecté, le concurrent qui voudrait faire "
            "inscrire une application légitime sur la blocklist, l'analyste interne "
            "malintentionné, l'attaquant réseau et l'application hostile installée à "
            "côté de l'agent."
        )
    )
    story.append(
        table(
            [
                ["Attaquant", "Contrôle principal"],
                ["Opérateur de fraude", "Défense en profondeur à quatre couches ; le "
                 "pipeline aboutit toujours, aucune entrée ne fait taire le moteur"],
                ["Concurrent malveillant", "Registre des applications officielles, "
                 "heuristiques conditionnées à la provenance, quatre yeux avant publication"],
                ["Analyste interne", "Séparation auteur / relecteur, journal d'audit "
                 "append-only, RBAC"],
                ["Attaquant réseau", "TLS, CSP stricte à nonce, en-têtes de sécurité, "
                 "limitation de débit par appelant, CORS fermé"],
                ["Application hostile locale", "L'agent n'expose pas de composant "
                 "exporté sensible et ne détient aucun secret réutilisable"],
            ],
            widths=[CONTENT_W * 0.25, CONTENT_W * 0.75],
        )
    )

    story.append(h2("Protection des données personnelles"))
    story.append(
        p(
            "Le dispositif est soumis à analyse d'impact : il traite à grande échelle et "
            "observe en continu les applications installées sur l'appareil d'une "
            "personne. L'analyse a néanmoins été conduite sur un traitement conçu pour "
            "ne manipuler <b>aucune donnée directement identifiante</b>."
        )
    )
    story.extend(
        bullets([
            "Ne sont pas collectés, et n'existent pas dans le schéma : numéro de "
            "téléphone, IMEI, IMSI, identité, compte financier, contenu des SMS, "
            "contacts, position GPS, adresse IP de l'appareil.",
            "L'identifiant d'agent est un UUID généré sur l'appareil, sans lien avec un "
            "identifiant matériel ou d'abonné ; la région est déclarative et grossière.",
            "La console n'offre <b>aucune vue par appareil</b> : uniquement des agrégats. "
            "Elle ne peut pas servir à surveiller une personne.",
            "Le retrait du consentement à la télémétrie n'enlève aucune protection : "
            "l'agent continue de fonctionner hors ligne.",
        ])
    )
    story.append(
        callout(
            "Le risque principal n'est pas la vie privée",
            "C'est le <b>faux positif</b>. Priver quelqu'un de son application de "
            "paiement, c'est le priver de son argent. Ce constat explique le registre "
            "des applications officielles avec épinglage de certificat, le "
            "conditionnement des heuristiques à la provenance, la règle des quatre yeux, "
            "et le fait que l'agent alerte au lieu de désinstaller.",
        )
    )

    story.append(PageBreak())

    # ---------------- Qualité ----------------
    story.append(h1("11. Qualité logicielle"))
    story.extend(
        figure("quality.png", "Couverture et répartition des tests par domaine.",
               CONTENT_W * 0.92)
    )
    story.extend(
        bullets([
            "<b>150 tests</b> automatisés, <b>94 %</b> de couverture, exécutés à chaque "
            "modification par l'intégration continue.",
            "Analyse statique <font face='Courier' size='8'>ruff</font> sans avertissement, "
            "SAST <font face='Courier' size='8'>bandit</font> sans constat, audit de "
            "dépendances <font face='Courier' size='8'>pip-audit</font> sans vulnérabilité "
            "connue.",
            "Deux chaînes d'intégration : une pour la plateforme Python, une pour l'agent "
            "Android, déclenchée sur toute modification du module mobile.",
            "Les tests portent sur les propriétés qui comptent — la règle des quatre yeux "
            "ne peut pas être contournée, une clé d'agent n'ouvre pas les statistiques, "
            "un jeton de session n'est jamais stocké en clair, un travail en échec ne tue "
            "pas le worker.",
        ])
    )
    story.extend(
        figure("codebase.png", "Répartition du code, mesurée sur le dépôt.", CONTENT_W * 0.88)
    )

    story.append(PageBreak())

    # ---------------- Bilan ----------------
    story.append(h1("12. Bilan et perspectives"))
    story.extend(figure("roadmap.png", "Les cinq phases du projet."))
    story.append(
        p(
            "Les cinq phases prévues sont livrées : moteur d'analyse, API de plateforme, "
            "agent Android, console et gouvernance, durcissement et déploiement. La "
            "plateforme est fonctionnelle de bout en bout — un échantillon peut être "
            "soumis, qualifié, transformé en indicateur, validé par deux analystes, "
            "distribué aux agents et partagé avec un CERT partenaire."
        )
    )

    story.append(h2("Ce qui reste ouvert"))
    story.extend(
        bullets([
            "<b>L'audit de sécurité externe</b> — un travail de tiers par nature. Le "
            "périmètre attendu est énoncé : test d'intrusion authentifié, revue "
            "cryptographique, fuzzing du moteur, revue de l'agent et de la chaîne de "
            "build.",
            "<b>La remise de la clé de signature nationale</b>, préalable à toute "
            "publication publique de l'agent.",
            "<b>Les migrations de schéma</b> — le schéma est créé au démarrage, ce qui "
            "suffit aujourd'hui ; une exploitation pluriannuelle demandera un outil de "
            "migration. C'est un choix d'exploitation à trancher avant la première montée "
            "de version en production.",
        ])
    )

    story.append(h2("Extensions naturelles"))
    story.extend(
        bullets([
            "<b>Analyse dynamique</b> en bac à sable, pour les échantillons que "
            "l'obfuscation rend opaques à l'analyse statique.",
            "<b>Ingestion de flux partenaires</b> dans le sens entrant : la plateforme "
            "exporte aujourd'hui, elle pourrait consommer les flux MISP des CERT voisins.",
            "<b>Corrélation régionale</b> : détecter l'apparition d'une campagne à partir "
            "de la dérive statistique de la télémétrie, plutôt qu'à partir d'un "
            "signalement.",
        ])
    )
    story.append(Spacer(1, 6))
    story.append(
        callout(
            "En une phrase",
            "FasoShield démontre qu'une capacité antivirus souveraine, adaptée à un "
            "paysage de menaces local que les produits mondiaux couvrent mal, tient dans "
            "une architecture simple, exploitable par une petite équipe, et gouvernée de "
            "manière à ce qu'aucune personne seule ne puisse se tromper au nom de tout un "
            "pays.",
        )
    )

    return story


def build() -> Path:
    doc = BaseDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
        title="FasoShield — Dossier de présentation",
        author=AUTHOR,
        subject=SUBTITLE,
    )

    cover_frame = Frame(MARGIN, MARGIN, CONTENT_W, PAGE_H - 2 * MARGIN, id="cover")
    content_frame = Frame(
        MARGIN, MARGIN + 4 * mm, CONTENT_W, PAGE_H - 2 * MARGIN - 8 * mm, id="content"
    )

    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=cover_page),
        PageTemplate(id="content", frames=[content_frame], onPage=content_page),
    ])

    doc.build(build_story())
    return OUTPUT


if __name__ == "__main__":
    path = build()
    print(f"PDF généré : {path}  ({path.stat().st_size // 1024} Kio)")
