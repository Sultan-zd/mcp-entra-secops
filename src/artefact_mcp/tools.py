"""Les outils d'analyse d'artefacts, tous entièrement locaux.

Un jeton est un secret ; une charge obfusquée peut être la pièce à conviction
d'un incident en cours. Ni l'un ni l'autre ne quitte le poste : c'est ce qui
permet de les analyser sans autorisation préalable ni bac à sable.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from . import decodage as dec
from . import jwt as jw
from .models import DecodedLayer, DecodedPayload, JwtAnalysis


async def analyze_jwt(
    token: Annotated[
        str,
        Field(
            description="Le jeton JWT. Le préfixe « Bearer » est toléré.",
            max_length=32768,
        ),
    ],
) -> JwtAnalysis:
    """Décode un jeton JWT et signale ce qui cloche — sans vérifier la signature.

    **Ce que cet outil répond**, et que la lecture à l'œil ne donne pas : que
    contient ce jeton, quelles permissions porte-t-il, et quels défauts de
    conception laisse-t-il voir.

    Ce qu'il cherche, du plus grave au moins grave :

    * **`alg: none`** — le jeton se déclare non signé. Un service qui l'accepte
      laisse n'importe qui fabriquer l'identité de son choix.
    * **`jku` / `x5u`** — l'en-tête désigne une URL de clé. Sans liste blanche
      côté service, un attaquant y place la sienne.
    * **Algorithme symétrique** là où un tiers doit pouvoir vérifier : qui
      vérifie peut alors forger.
    * **Pas d'expiration**, ou jeton expiré, ou durée de vie très longue.
    * **Pas d'audience** : le jeton peut être rejoué contre un autre service.

    Pour un jeton Microsoft Entra, les portées (`scp`) et rôles applicatifs
    (`roles`) sont rendus en clair : c'est ce que le porteur peut réellement
    faire.

    `signature_verified` vaut **toujours faux**. Vérifier exigerait la clé de
    l'émetteur ; ce jeton est lisible, son authenticité n'est pas établie.

    Rien n'est envoyé nulle part : expédier un jeton pour l'analyser serait le
    divulguer.
    """
    lu = jw.auditer(jw.lire(token))
    return JwtAnalysis(
        algorithm=lu.algorithm,
        token_type=lu.token_type,
        key_id=lu.key_id,
        issuer=lu.issuer,
        subject=lu.subject,
        audience=lu.audience,
        issued_at=lu.issued_at,
        expires_at=lu.expires_at,
        expired=lu.expired,
        seconds_remaining=lu.seconds_remaining,
        lifetime_seconds=lu.lifetime_seconds,
        permissions=lu.permissions,
        header=lu.header,
        claims=lu.claims,
        signature_verified=False,
        findings=lu.findings,
        notes=lu.notes,
    )


async def decode_payload(
    payload: Annotated[
        str,
        Field(
            description="La charge encodée : base64, hexadécimal, URL, gzip — ou un empilement.",
            max_length=1_048_576,
        ),
    ],
    max_depth: Annotated[
        int,
        Field(description="Nombre maximal de couches à retirer.", ge=1, le=16),
    ] = 8,
) -> DecodedPayload:
    """Retire les couches d'encodage d'une charge obfusquée, et dit lesquelles.

    Devant `powershell -enc SQBFAFgA...`, l'extraction d'indicateurs ne voit
    rien : il n'y a rien à voir tant que la couche n'est pas retirée. Cet outil
    la retire, puis la suivante, jusqu'à obtenir du texte lisible.

    **Les couches traversées sont rendues**, dans l'ordre. Elles importent
    autant que le résultat : un empilement de trois encodages caractérise
    l'outillage employé, là où une charge légitime en compte rarement plus d'un.

    Deux comportements à connaître :

    * Un décodage n'est retenu que s'il **améliore** la charge. Un texte en
      clair dont l'alphabet ressemble à du base64 n'est pas « décodé » en
      octets aléatoires.
    * Si le résultat est un **fichier** — exécutable, archive, document — il
      est reconnu à sa signature et rendu en hexadécimal, avec un avertissement.
      Son empreinte suffit à l'identifier ; il n'a pas à être exécuté.

    Cet outil ne fait que décoder. Il n'exécute rien, ne désassemble rien,
    n'interprète aucun script — c'est ce qui permet de s'en servir sans bac à
    sable.
    """
    resultat = dec.decoder(payload, profondeur_max=max_depth)
    return DecodedPayload(
        decoded=resultat.decoded,
        layers=[DecodedLayer(encoding=c.encoding, detail=c.detail) for c in resultat.layers],
        file_type=resultat.file_type,
        is_text=resultat.is_text,
        truncated=resultat.truncated,
        findings=resultat.findings,
        notes=resultat.notes,
    )
