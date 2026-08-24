"""Transport HTTP : partager un serveur ARGUS entre plusieurs analystes.

**Ce que ce module change, et ce qu'il ne change pas.** En stdio, le client
lance lui-même le processus : aucun port n'est ouvert, la surface réseau est
*nulle*. C'est le mode le plus sûr, et il reste **celui par défaut**.

Le transport HTTP existe pour deux besoins que stdio ne peut pas couvrir :
partager une instance entre plusieurs analystes, et servir des clients qui ne
savent pas lancer de processus local. Il ouvre un port — donc il faut le
protéger.

**Streamable HTTP, jamais SSE.** La révision `2026-07-28` de la spécification
classe HTTP+SSE comme *déprécié*, donc supprimable dans une révision future.
Le brief technique du projet écarte explicitement cette piste.

Trois protections, dont deux que ce module rend impossibles à oublier :

1. **Écoute sur la boucle locale par défaut.** Un port ouvert sur toutes les
   interfaces expose 46 outils de sécurité, et les identifiants de tenant qui
   vont avec, à quiconque atteint la machine.
2. **Validation de l'en-tête `Origin`.** Sans elle, une page web visitée par
   l'analyste peut piloter son serveur local — c'est l'attaque par
   *rebinding DNS*. Le SDK l'assure ; ce module ne la désactive jamais.
3. **Jeton obligatoire hors de la boucle locale.** Le serveur **refuse de
   démarrer** sur une interface publique sans jeton. C'est le garde-fou qui
   compte : la commande dangereuse est plus courte à taper que la commande
   sûre, et l'oubli n'est pas rattrapable après coup.

**Ce que ce module n'est pas.** Ce n'est pas un déploiement OAuth 2.1 complet.
Le jeton est un secret partagé, vérifié par comparaison à temps constant. La
cible de production reste un proxy inverse assurant TLS et une validation de
jeton par l'IdP de l'entreprise — la forme est déjà celle d'un serveur de
ressource, si bien que la migration remplacera ce vérificateur sans toucher au
reste.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging

from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

logger = logging.getLogger(__name__)

#: Le jeton partagé, lu dans l'environnement.
VARIABLE_JETON = "ARGUS_HTTP_TOKEN"

#: Longueur minimale acceptée. Un jeton court se devine ; l'imposer ici évite
#: qu'un « test » de trois lettres finisse en production.
LONGUEUR_MINIMALE = 16


class ConfigurationHttpError(RuntimeError):
    """La configuration demandée exposerait le serveur sans protection."""


def est_boucle_locale(hote: str) -> bool:
    """L'adresse d'écoute reste-t-elle sur la machine ?

    `localhost` est traité comme la boucle locale ; toute adresse non résoluble
    est considérée comme *publique*, parce que se tromper dans ce sens ferme le
    serveur au lieu de l'ouvrir.
    """
    nom = hote.strip().lower()
    if nom in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(nom).is_loopback
    except ValueError:
        return False


class JetonPartage:
    """Vérificateur de jeton à secret partagé.

    Implémente le protocole `TokenVerifier` du SDK. La comparaison passe par
    `hmac.compare_digest` : un `==` ordinaire s'interrompt au premier octet
    different, ce qui laisse mesurer le préfixe correct et reconstituer le
    jeton octet par octet.
    """

    def __init__(self, secret: str) -> None:
        self._secret = secret

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token, self._secret):
            return None
        return AccessToken(
            token=token,
            client_id="argus-http",
            scopes=["argus:read"],
        )


def resoudre_jeton(hote: str, jeton: str | None) -> str | None:
    """Décide si le serveur peut démarrer, et avec quel jeton.

    C'est ici que se joue la seule décision de sécurité irréversible : accepter
    de servir sans authentification. Elle est prise en un seul endroit, testable,
    plutôt que dispersée dans le point d'entrée.
    """
    valeur = (jeton or "").strip()
    local = est_boucle_locale(hote)

    if not valeur:
        if not local:
            raise ConfigurationHttpError(
                f"Refus de démarrer : l'écoute sur « {hote} » exposerait 46 outils de "
                f"sécurité sans authentification.\n"
                f"  Définissez {VARIABLE_JETON} (au moins {LONGUEUR_MINIMALE} caractères), "
                f"ou gardez l'écoute sur 127.0.0.1."
            )
        logger.warning(
            "Aucun jeton : le serveur n'accepte que la boucle locale, mais tout "
            "programme tournant sur cette machine peut l'interroger. Définissez "
            "%s pour exiger une authentification.",
            VARIABLE_JETON,
        )
        return None

    if len(valeur) < LONGUEUR_MINIMALE:
        raise ConfigurationHttpError(
            f"{VARIABLE_JETON} fait {len(valeur)} caractères ; "
            f"{LONGUEUR_MINIMALE} au minimum. Un jeton court se devine."
        )

    return valeur


def exiger_chiffrement(hote: str, *, tls_local: bool, tls_en_amont: bool) -> None:
    """Refuse de servir en clair au-delà de la machine.

    **Pourquoi c'est un refus et non un avertissement.** Le jeton
    d'authentification voyage dans un en-tête `Authorization`. Sans TLS, il
    traverse le réseau en clair à *chaque* requête : quiconque observe le
    trafic le récupère, et obtient les 46 outils, les journaux du tenant et les
    clés de réputation qui vont avec. Un avertissement au démarrage défile et
    disparaît ; le refus, non.

    L'échappatoire est explicite (`--tls-en-amont`) parce que le déploiement
    recommandé — un proxy inverse qui termine TLS — est parfaitement légitime,
    et que le serveur ne peut pas le constater lui-même. La déclarer à la main
    est le prix de cette impossibilité.
    """
    if est_boucle_locale(hote) or tls_local or tls_en_amont:
        return

    raise ConfigurationHttpError(
        f"Refus de servir en clair sur « {hote} » : le jeton d'authentification "
        "circulerait en clair à chaque requête.\n"
        "  Trois issues :\n"
        "    --tls-cert / --tls-key   terminer TLS ici même\n"
        "    --tls-en-amont           un proxy inverse s'en charge déjà\n"
        "    --host 127.0.0.1         ne pas sortir de la machine"
    )


def schema(*, chiffre: bool) -> str:
    """`https` dès que la connexion est chiffrée, ici ou en amont.

    Le schéma n'est pas cosmétique : il entre dans les origines autorisées et
    dans l'URL du serveur de ressource. Annoncer `http://` là où le client
    parle `https://` fait rejeter des requêtes parfaitement légitimes.
    """
    return "https" if chiffre else "http"


def parametres_auth(
    jeton: str | None, hote: str, port: int, *, chiffre: bool = False
) -> AuthSettings | None:
    """Construit la configuration d'authentification attendue par le SDK.

    Le SDK refuse un vérificateur de jeton sans `AuthSettings`, qui exige une
    URL d'émetteur et une URL de serveur de ressource. Le serveur est ici son
    propre émetteur : c'est la forme d'un serveur de ressource OAuth, remplie
    par un secret partagé.
    """
    if jeton is None:
        return None

    base = AnyHttpUrl(f"{schema(chiffre=chiffre)}://{hote}:{port}")
    return AuthSettings(
        issuer_url=base,
        resource_server_url=base,
        required_scopes=["argus:read"],
    )


def parametres_securite(
    hote: str,
    port: int,
    origines: list[str] | None = None,
    *,
    chiffre: bool = False,
) -> TransportSecuritySettings:
    """Protection contre le rebinding DNS, jamais désactivée.

    Sans validation de `Origin`, une page web ouverte par l'analyste peut faire
    exécuter des requêtes à son serveur local : le navigateur les émet, et le
    serveur les traite comme légitimes.
    """
    proto = schema(chiffre=chiffre)
    autorises = origines or [f"{proto}://{hote}:{port}", f"{proto}://localhost:{port}"]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"{hote}:{port}", f"localhost:{port}"],
        allowed_origins=autorises,
    )
