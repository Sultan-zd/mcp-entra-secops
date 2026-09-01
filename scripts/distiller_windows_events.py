"""Distille deux références Windows en un jeu embarquable.

Deux sources, deux natures — volontairement pas fusionnées en une seule
échelle :

* **Audit de sécurité Windows** (canal `Security`, IDs 4xxx/5xxx/6xx). Source :
  « Appendix L: Events to Monitor », un tableau tenu à jour par Microsoft dans
  `MicrosoftDocs/windowsserverdocs`. Chaque ligne porte une **criticité**
  (`Low` à `High`) — un jugement éditorial de Microsoft sur l'intérêt de
  surveiller cet événement, absent de la documentation individuelle par ID.
* **Sysmon** (canal `Microsoft-Windows-Sysmon/Operational`, IDs 1-29 et 255).
  Source : la page officielle Sysinternals. **Aucune criticité n'y est
  publiée** — Sysmon journalise ce que sa configuration lui demande, et
  l'intérêt d'un événement dépend entièrement de cette configuration. Inventer
  une note ici reviendrait à afficher un jugement que Microsoft ne porte pas :
  le champ n'existe donc pas sur ces entrées, plutôt que d'être rempli par
  approximation.

Usage :
    python scripts/distiller_windows_events.py
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

SOURCE_SECURITE = (
    "https://raw.githubusercontent.com/MicrosoftDocs/windowsserverdocs/main/"
    "WindowsServerDocs/identity/ad-ds/plan/Appendix-L--Events-to-Monitor.md"
)
SOURCE_SYSMON = (
    "https://raw.githubusercontent.com/MicrosoftDocs/sysinternals/main/"
    "sysinternals/downloads/sysmon.md"
)

DESTINATION = (
    Path(__file__).parent.parent / "src" / "detection_mcp" / "fixtures" / "windows_events.json"
)

LIGNE_TABLEAU = re.compile(
    r"^\|(?P<courant>\d+|N/A)\|(?P<legacy>[^|]*)\|(?P<crit>[^|]*)\|(?P<resume>[^|]*)\|$"
)
TITRE_SYSMON = re.compile(r"^###\s*Event ID\s*(\d+):\s*(.+)$", re.MULTILINE)


def _telecharger(url: str) -> str:
    entetes = {"User-Agent": "Mozilla/5.0"}
    requete = urllib.request.Request(url, headers=entetes)  # noqa: S310
    with urllib.request.urlopen(requete, timeout=30) as reponse:  # noqa: S310
        return str(reponse.read().decode("utf-8"))


def _developper_legacy(brut: str) -> list[str]:
    """« 529-537,539 » → chaque identifiant listé individuellement."""
    if brut.strip() in ("", "N/A"):
        return []
    resultat: list[str] = []
    for morceau in brut.split(","):
        morceau = morceau.strip()
        if "-" in morceau:
            debut, fin = morceau.split("-", 1)
            resultat.extend(str(n) for n in range(int(debut), int(fin) + 1))
        elif morceau:
            resultat.append(morceau)
    return resultat


def _distiller_securite(markdown: str) -> list[dict[str, object]]:
    evenements: list[dict[str, object]] = []
    for ligne in markdown.splitlines():
        m = LIGNE_TABLEAU.match(ligne.strip())
        if not m:
            continue
        courant = m.group("courant").strip()
        evenements.append(
            {
                "current_id": None if courant == "N/A" else courant,
                "legacy_ids": _developper_legacy(m.group("legacy")),
                "criticality": m.group("crit").strip(),
                "summary": m.group("resume").strip(),
            }
        )
    return evenements


def _distiller_sysmon(markdown: str) -> list[dict[str, object]]:
    positions = list(TITRE_SYSMON.finditer(markdown))
    evenements: list[dict[str, object]] = []
    for i, m in enumerate(positions):
        fin = positions[i + 1].start() if i + 1 < len(positions) else len(markdown)
        corps = markdown[m.end() : fin]
        # Le premier paragraphe non vide, débarrassé des sauts de ligne internes.
        paragraphe = corps.strip().split("\n\n", 1)[0]
        description = " ".join(paragraphe.split())
        evenements.append(
            {
                "id": int(m.group(1)),
                "name": m.group(2).strip(),
                "description": description,
            }
        )
    return evenements


def main() -> None:
    print(f"Téléchargement depuis {SOURCE_SECURITE} …")
    md_securite = _telecharger(SOURCE_SECURITE)
    print(f"Téléchargement depuis {SOURCE_SYSMON} …")
    md_sysmon = _telecharger(SOURCE_SYSMON)

    securite = _distiller_securite(md_securite)
    sysmon = _distiller_sysmon(md_sysmon)

    if len(securite) < 300:
        raise SystemExit(f"Tableau de sécurité anormalement court : {len(securite)} lignes.")
    if len(sysmon) < 25:
        raise SystemExit(f"Liste Sysmon anormalement courte : {len(sysmon)} entrées.")

    resultat = {
        "security": {
            "source": (
                "Microsoft Learn — Appendix L: Events to Monitor "
                "(MicrosoftDocs/windowsserverdocs)"
            ),
            "count": len(securite),
            "events": securite,
        },
        "sysmon": {
            "source": "Microsoft Learn — Sysmon (Sysinternals)",
            "count": len(sysmon),
            "events": sysmon,
        },
    }

    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(
        json.dumps(resultat, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )

    poids = DESTINATION.stat().st_size / 1024
    print(
        f"{DESTINATION} écrit : {len(securite)} événements sécurité, "
        f"{len(sysmon)} événements Sysmon, {poids:.0f} Ko"
    )


if __name__ == "__main__":
    main()
