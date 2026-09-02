"""Outils d'accès conditionnel et de contexte utilisateur."""

from __future__ import annotations

import logging
from typing import Annotated

from pydantic import Field

from ..config import get_settings
from ..graph import GraphError
from ..models import ConditionalAccessPolicy, ConditionalAccessReport, UserContext
from ..runtime import get_client
from .odata import escape_odata

logger = logging.getLogger(__name__)

POLICIES_ENDPOINT = "/identity/conditionalAccess/policies"
USERS_ENDPOINT = "/users"

#: Champs demandés à Graph pour la fiche utilisateur. Restreindre le `$select`
#: est la première étape de la troncature : ce qui n'est pas demandé n'est même
#: pas transféré sur le réseau.
_USER_FIELDS = (
    "id,displayName,userPrincipalName,jobTitle,department,accountEnabled,createdDateTime,userType"
)


async def get_conditional_access_policies(
    limit: Annotated[
        int | None,
        Field(description="Nombre maximum de politiques. Défaut 25, borné à 100.", ge=1),
    ] = None,
) -> ConditionalAccessReport:
    """Liste les politiques d'accès conditionnel du tenant, avec leur état réel
    d'application.

    À utiliser pour expliquer pourquoi une connexion a été bloquée (code 53003),
    ou pour repérer une faille de couverture : politique désactivée, politique en
    mode audit seul, ou exclusion qui permet à un compte de contourner un contrôle.
    """
    settings = get_settings()
    size = settings.clamp_limit(limit)

    logger.info("Lecture des politiques d'accès conditionnel (max %d).", size)
    raw = await get_client().get(POLICIES_ENDPOINT, params={"$top": size}, max_items=size)

    policies = [ConditionalAccessPolicy.from_graph(item) for item in raw]
    policies.sort(key=lambda p: (not p.is_enforced, p.name))
    return ConditionalAccessReport.build(policies)


async def get_user_context(
    upn: Annotated[
        str,
        Field(description="User Principal Name complet, par exemple « alice@contoso.com »."),
    ],
) -> UserContext:
    """Récupère la fiche d'identité d'un compte : poste, département, état,
    groupes d'appartenance et rôles d'annuaire détenus.

    C'est l'outil qui détermine la GRAVITÉ d'un incident. Une connexion suspecte
    sur un compte sans privilège et sur un compte administrateur global appellent
    des réponses très différentes.

    À appeler systématiquement avant de conclure sur un incident.
    """
    client = get_client()

    logger.info("Lecture du contexte de %s.", upn)
    users = await client.get(
        USERS_ENDPOINT,
        params={
            "$filter": f"userPrincipalName eq '{escape_odata(upn)}'",
            "$select": _USER_FIELDS,
            "$top": 1,
        },
        max_items=1,
    )
    if not users:
        raise GraphError(
            f"Aucun compte ne correspond à l'UPN « {upn} » dans l'annuaire. "
            "Vérifiez l'orthographe : l'UPN doit être complet, domaine inclus."
        )

    user = users[0]
    object_id = user.get("id")
    if not object_id:
        # Sans identifiant d'objet, l'appartenance aux groupes est inatteignable.
        # Mieux vaut une fiche partielle qu'un échec complet de l'outil.
        logger.warning("Compte %s sans identifiant d'objet : appartenances ignorées.", upn)
        return UserContext.build(user, [])

    # `memberOf` exige `Directory.Read.All`, une permission plus large que le
    # `User.Read.All` qui suffit à lire la fiche elle-même. Un tenant accordé
    # au plus juste peut donc répondre 403 ICI alors que tout le reste a
    # fonctionné. Rendre une fiche partielle vaut mieux qu'un échec total —
    # à condition que l'ignorance soit dite : sans cela, `is_privileged=false`
    # présenterait un administrateur global comme un compte ordinaire.
    try:
        memberships = await client.get(f"{USERS_ENDPOINT}/{object_id}/memberOf")
    except GraphError as exc:
        logger.warning("Appartenances de %s illisibles : %s", upn, exc)
        return UserContext.build(
            user, [], memberships_readable=False, raison_illisible=str(exc)
        )
    return UserContext.build(user, memberships)
