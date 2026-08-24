"""Genere l'icone du paquet MCPB.

    python mcpb/outils/generer_icone.py

Le motif est un oeil : Argus Panoptes, le geant aux cent yeux de la mythologie
grecque, etait le gardien qui ne dormait jamais. C'est aussi ce que fait un
SOC.

**Pourquoi un script et pas un fichier binaire depose la.** Une icone opaque
dans un depot ne se modifie plus : personne ne sait avec quoi elle a ete faite.
Ici, changer une couleur ou une proportion se fait en une ligne, et le resultat
est reproductible.

Pillow n'est requis que pour executer ce script, jamais pour utiliser ARGUS :
l'icone produite est versionnee, le paquet ne depend pas de Pillow.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - uniquement pour le typage
    from PIL.Image import Image as ImagePIL

# Palette : ardoise profonde et cyan froid. Deux contraintes ont guide le
# choix — rester lisible a 32 px dans une liste d'extensions, et se distinguer
# sur un fond clair comme sur un fond sombre.
FOND = (15, 23, 42)  # ardoise
IRIS = (34, 211, 238)  # cyan
IRIS_SOMBRE = (14, 116, 144)
PUPILLE = (8, 12, 24)
BLANC = (226, 232, 240)

COTE = 512
RAYON_COINS = 112

#: Demi-axes de l'oeil. La hauteur vaut environ les deux tiers de la largeur :
#: au-dela, l'amande devient un cercle et perd sa lecture d'oeil.
DEMI_LARGEUR = 170
DEMI_HAUTEUR = 108


def _amande(marge: int = 0) -> ImagePIL:
    """Le masque de l'oeil : deux ellipses qui se recoupent.

    Une ellipse unique donnerait des commissures arrondies. L'intersection de
    deux ellipses decalees verticalement produit les pointes, qui sont ce qui
    fait lire la forme comme un oeil.
    """
    from PIL import Image, ImageChops, ImageDraw

    centre = COTE // 2
    largeur = DEMI_LARGEUR + marge
    hauteur = DEMI_HAUTEUR + marge

    haute = Image.new("L", (COTE, COTE), 0)
    ImageDraw.Draw(haute).ellipse(
        [centre - largeur, centre - hauteur * 2, centre + largeur, centre + hauteur],
        fill=255,
    )
    basse = Image.new("L", (COTE, COTE), 0)
    ImageDraw.Draw(basse).ellipse(
        [centre - largeur, centre - hauteur, centre + largeur, centre + hauteur * 2],
        fill=255,
    )
    return ImageChops.multiply(haute, basse)


def dessiner() -> ImagePIL:
    from PIL import Image, ImageDraw

    image = Image.new("RGBA", (COTE, COTE), (0, 0, 0, 0))
    dessin = ImageDraw.Draw(image)
    centre = COTE // 2

    # --- fond arrondi -----------------------------------------------------
    dessin.rounded_rectangle(
        [(0, 0), (COTE - 1, COTE - 1)], radius=RAYON_COINS, fill=(*FOND, 255)
    )

    # --- liseré, puis blanc de l'oeil par-dessus --------------------------
    # L'ordre compte : le liseré est une amande legerement plus grande, dont
    # seule la couronne reste visible une fois le blanc pose dessus.
    image.paste(Image.new("RGBA", (COTE, COTE), (*IRIS_SOMBRE, 255)), (0, 0), _amande(marge=7))
    image.paste(Image.new("RGBA", (COTE, COTE), (*BLANC, 255)), (0, 0), _amande())

    # --- iris -------------------------------------------------------------
    rayon_iris = 78
    dessin.ellipse(
        [centre - rayon_iris, centre - rayon_iris, centre + rayon_iris, centre + rayon_iris],
        fill=(*IRIS, 255),
        outline=(*IRIS_SOMBRE, 255),
        width=6,
    )

    rayon_pupille = 34
    dessin.ellipse(
        [centre - rayon_pupille, centre - rayon_pupille,
         centre + rayon_pupille, centre + rayon_pupille],
        fill=(*PUPILLE, 255),
    )

    # Reflet : sans lui, l'oeil parait eteint a petite taille.
    dessin.ellipse([centre + 14, centre - 46, centre + 44, centre - 16], fill=(255, 255, 255, 220))

    return image


def main() -> None:
    cible = Path(__file__).resolve().parent.parent / "icon.png"
    dessiner().save(cible, "PNG", optimize=True)
    poids = cible.stat().st_size // 1024
    print(f"  ✓ {cible.name} — {COTE} px, {poids} Ko")


if __name__ == "__main__":
    main()
