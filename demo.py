"""Démonstration : enchaîne les outils sur le scénario d'incident intégré.

    python demo.py

Fonctionne sans tenant Azure tant que ENTRA_DATA_SOURCE=fixture (valeur du
fichier .env.example). Passez à ENTRA_DATA_SOURCE=graph pour interroger un vrai
tenant, avec les identifiants correspondants dans .env.
"""

import asyncio

from entra_secops_mcp.runtime import configure_logging, lifespan
from entra_secops_mcp.tools.access import get_conditional_access_policies, get_user_context
from entra_secops_mcp.tools.audits import get_directory_audits
from entra_secops_mcp.tools.identity import get_risk_detections
from entra_secops_mcp.tools.signins import get_user_signins

CIBLE = "marketing@teknologiia.com"


def titre(texte: str) -> None:
    print()
    print(texte)
    print("-" * len(texte))


def notes(elements: list[str]) -> None:
    for note in elements:
        print("  !", note)
    if not elements:
        print("  (aucune observation particulière)")


async def main() -> None:
    # Sur stderr, pour ne pas polluer la sortie de la démonstration.
    configure_logging("WARNING")

    async with lifespan(None):
        titre(f"1. Qui est {CIBLE} ?")
        contexte = await get_user_context(CIBLE)
        print(f"  Poste       : {contexte.job_title} ({contexte.department})")
        print(f"  Groupes     : {', '.join(contexte.groups)}")
        print(f"  Rôles       : {', '.join(contexte.directory_roles) or 'aucun'}")
        print(f"  Privilégié  : {contexte.is_privileged}")
        notes(contexte.notes)

        titre("2. Que s'est-il passé sur l'authentification ?")
        signins = await get_user_signins(CIBLE)
        print(
            f"  {signins.total_events} événements sur {signins.window_hours} h — "
            f"{signins.failures} échecs, {signins.successes} succès"
        )
        print(f"  IP observées : {', '.join(signins.distinct_ip_addresses)}")
        notes(signins.notes)

        titre("3. Qu'a détecté Identity Protection ?")
        risques = await get_risk_detections(upn=CIBLE)
        print(f"  {risques.total_detections} détections : {', '.join(risques.distinct_types)}")
        notes(risques.notes)

        titre("4. Qu'a fait l'attaquant une fois entré ?")
        audits = await get_directory_audits(hours=168)
        print(
            f"  {audits.total_entries} modifications, "
            f"dont {audits.sensitive_entries} sensibles"
        )
        for entree in audits.entries:
            if entree.security_note:
                print(f"    · {entree.activity} — par {entree.initiated_by}")
        notes(audits.notes)

        titre("5. Nos politiques d'accès conditionnel tiennent-elles ?")
        politiques = await get_conditional_access_policies()
        print(
            f"  {politiques.total_policies} politiques — {politiques.enforced} appliquées, "
            f"{politiques.report_only} en audit seul, {politiques.disabled} désactivées"
        )
        notes(politiques.notes)


if __name__ == "__main__":
    asyncio.run(main())
