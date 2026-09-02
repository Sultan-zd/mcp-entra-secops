"""Lecture et audit d'un jeton JWT, entièrement hors ligne.

**Pourquoi ce module lit sans vérifier.** Vérifier une signature exige la clé
de l'émetteur, que l'analyste n'a pas — et ce n'est pas ce qu'il cherche. Un
jeton arrive dans un ticket, un en-tête capturé, un journal : la question est
« que contient-il, et qu'est-ce qui cloche ? », pas « est-il authentique ? ».

Le module le dit clairement plutôt que de laisser croire à une validation :
`signature_verified` vaut toujours faux, et le champ existe pour qu'on ne
puisse pas l'oublier.

**Ce que l'audit cherche**, par ordre de gravité :

* `alg: none` — le jeton se déclare non signé. Un serveur qui l'accepte laisse
  n'importe qui fabriquer l'identité de son choix. C'est une faille classique,
  toujours rencontrée.
* Un algorithme **symétrique** (`HS*`) là où l'émetteur est un service public :
  la clé de vérification est aussi la clé de signature, donc quiconque peut
  vérifier peut forger.
* Un jeton **expiré**, ou sans `exp` du tout — un jeton sans expiration reste
  valable jusqu'à révocation de la clé.
* Une **audience absente** : un jeton émis pour un service peut alors être
  rejoué contre un autre. C'est l'attaque du député confus.

Rien n'est envoyé nulle part : un jeton est un secret, l'expédier pour
l'analyser serait le divulguer.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: Algorithmes symétriques : la clé qui vérifie est celle qui signe.
SYMETRIQUES = frozenset({"HS256", "HS384", "HS512"})

#: Algorithmes que la norme décourage ou que les bibliothèques traitent mal.
FAIBLES = {
    "none": "le jeton se déclare NON SIGNÉ",
    "hs1": "algorithme non standard",
    "rs1": "SHA-1, cassé pour la signature",
}

#: Revendications dont l'absence change la sécurité du jeton.
ATTENDUES = {
    "exp": "expiration",
    "iat": "date d'émission",
    "aud": "audience",
    "iss": "émetteur",
    "sub": "sujet",
}

#: Revendications propres à Microsoft Entra, utiles à nommer en clair.
ENTRA = {
    "scp": "portées déléguées (au nom d'un utilisateur)",
    "roles": "rôles applicatifs (sans utilisateur)",
    "tid": "identifiant de tenant",
    "appid": "identifiant de l'application appelante",
    "upn": "nom principal de l'utilisateur",
    "idtyp": "type d'identité (app ou user)",
}


class JwtError(ValueError):
    """Le jeton n'a pas pu être lu."""


@dataclass
class Jeton:
    """Ce qu'un JWT contient, une fois décodé."""

    algorithm: str | None = None
    token_type: str | None = None
    key_id: str | None = None
    header: dict[str, Any] = field(default_factory=dict)
    claims: dict[str, Any] = field(default_factory=dict)
    issuer: str | None = None
    subject: str | None = None
    audience: list[str] = field(default_factory=list)
    issued_at: str | None = None
    expires_at: str | None = None
    expired: bool | None = None
    seconds_remaining: int | None = None
    lifetime_seconds: int | None = None
    permissions: list[str] = field(default_factory=list)
    signature_verified: bool = False
    findings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _base64url(segment: str) -> bytes:
    """Décode un segment base64url, en rétablissant le remplissage.

    Les JWT retirent le `=` final : le rajouter est indispensable, et c'est
    l'erreur la plus fréquente quand on décode un jeton à la main.
    """
    reste = len(segment) % 4
    if reste:
        segment += "=" * (4 - reste)
    try:
        return base64.urlsafe_b64decode(segment)
    except (binascii.Error, ValueError) as exc:
        raise JwtError(f"Segment illisible en base64url : {exc}") from exc


def _horodatage(valeur: Any) -> tuple[str | None, datetime | None]:
    if not isinstance(valeur, int | float):
        return None, None
    try:
        moment = datetime.fromtimestamp(float(valeur), tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None, None
    return moment.isoformat(), moment


def lire(jeton: str) -> Jeton:
    """Décode un JWT sans vérifier sa signature."""
    brut = (jeton or "").strip()
    if not brut:
        raise JwtError("Aucun jeton fourni.")

    # Un jeton copié depuis un en-tête traîne souvent son préfixe.
    for prefixe in ("Bearer ", "bearer ", "Authorization: Bearer "):
        if brut.startswith(prefixe):
            brut = brut[len(prefixe):].strip()
            break

    segments = brut.split(".")
    if len(segments) == 5:
        raise JwtError(
            "Ce jeton comporte cinq segments : c'est un JWE (chiffré), pas un JWS. "
            "Son contenu ne peut pas être lu sans la clé de déchiffrement."
        )
    if len(segments) != 3:
        raise JwtError(
            f"Un JWT compte trois segments séparés par des points ; celui-ci en a "
            f"{len(segments)}."
        )

    resultat = Jeton()

    try:
        resultat.header = json.loads(_base64url(segments[0]))
    except json.JSONDecodeError as exc:
        raise JwtError(f"En-tête illisible : {exc}") from exc
    try:
        resultat.claims = json.loads(_base64url(segments[1]))
    except json.JSONDecodeError as exc:
        raise JwtError(f"Charge utile illisible : {exc}") from exc

    if not isinstance(resultat.claims, dict):
        raise JwtError("La charge utile n'est pas un objet JSON.")

    resultat.algorithm = resultat.header.get("alg")
    resultat.token_type = resultat.header.get("typ")
    resultat.key_id = resultat.header.get("kid")

    revendications = resultat.claims
    resultat.issuer = revendications.get("iss")
    resultat.subject = revendications.get("sub")

    audience = revendications.get("aud")
    if isinstance(audience, str):
        resultat.audience = [audience]
    elif isinstance(audience, list):
        resultat.audience = [str(a) for a in audience]

    resultat.issued_at, emis = _horodatage(revendications.get("iat"))
    resultat.expires_at, expire = _horodatage(revendications.get("exp"))

    if expire:
        delta = (expire - datetime.now(UTC)).total_seconds()
        resultat.expired = delta <= 0
        resultat.seconds_remaining = int(delta)
    if emis and expire:
        resultat.lifetime_seconds = int((expire - emis).total_seconds())

    # --- permissions, en clair -------------------------------------------
    portees = revendications.get("scp")
    if isinstance(portees, str):
        resultat.permissions = portees.split()
    elif isinstance(portees, list):
        resultat.permissions = [str(p) for p in portees]
    roles = revendications.get("roles")
    if isinstance(roles, list):
        resultat.permissions += [str(r) for r in roles]

    resultat.notes.append(
        "La signature n'est PAS vérifiée : cela exigerait la clé de l'émetteur. "
        "Ce que ce jeton contient est lisible ; qu'il soit authentique ne l'est pas."
    )
    return resultat


def auditer(jeton: Jeton) -> Jeton:
    """Ajoute les constats de sécurité au jeton déjà lu."""
    algorithme = (jeton.algorithm or "").strip()
    bas = algorithme.lower()

    if not algorithme:
        jeton.findings.append("L'en-tête ne déclare aucun algorithme (`alg`).")
    elif bas == "none":
        jeton.findings.append(
            "`alg: none` — le jeton se déclare NON SIGNÉ. Un service qui "
            "l'accepte laisse n'importe qui fabriquer l'identité de son choix. "
            "C'est la faille JWT la plus classique."
        )
    elif bas in FAIBLES:
        jeton.findings.append(f"Algorithme « {algorithme} » : {FAIBLES[bas]}.")
    elif algorithme.upper() in SYMETRIQUES:
        jeton.findings.append(
            f"Algorithme symétrique « {algorithme} » : la clé qui vérifie est "
            "celle qui signe. Acceptable entre deux services qui la partagent, "
            "dangereux dès qu'un tiers doit pouvoir vérifier — il pourrait alors "
            "forger."
        )

    if jeton.header.get("jku") or jeton.header.get("x5u"):
        jeton.findings.append(
            "L'en-tête désigne une URL de clé (`jku`/`x5u`). Si le service la "
            "suit sans liste blanche, un attaquant peut y placer sa propre clé."
        )

    # --- durée de vie -----------------------------------------------------
    if "exp" not in jeton.claims:
        jeton.findings.append(
            "Aucune expiration (`exp`) : le jeton reste valable jusqu'à "
            "révocation de la clé de signature."
        )
    elif jeton.expired:
        jeton.findings.append(
            f"Jeton EXPIRÉ (le {jeton.expires_at}). Un service qui l'accepte "
            "encore ne contrôle pas l'expiration."
        )
    elif jeton.lifetime_seconds and jeton.lifetime_seconds > 24 * 3600:
        heures = jeton.lifetime_seconds // 3600
        jeton.findings.append(
            f"Durée de vie de {heures} heures : une fenêtre longue pour un jeton "
            "volé, qui reste utilisable jusqu'à son terme."
        )

    if not jeton.audience:
        jeton.findings.append(
            "Aucune audience (`aud`) : rien n'empêche de rejouer ce jeton contre "
            "un autre service que celui pour lequel il a été émis."
        )
    elif "*" in jeton.audience:
        jeton.findings.append("Audience « * » : le jeton vaut pour n'importe quel service.")

    manquantes = [
        libelle for cle, libelle in ATTENDUES.items() if cle not in jeton.claims
    ]
    if manquantes:
        jeton.notes.append("Revendications standard absentes : " + ", ".join(manquantes) + ".")

    # --- lecture des permissions -----------------------------------------
    if jeton.permissions:
        larges = [p for p in jeton.permissions if p.lower().endswith((".all", "readwrite.all"))]
        if larges:
            jeton.findings.append(
                f"{len(larges)} permission(s) à portée large : "
                + ", ".join(sorted(larges)[:6])
                + ". Un jeton compromis emporte tout ce périmètre."
            )
    presentes = [f"{c} ({libelle})" for c, libelle in ENTRA.items() if c in jeton.claims]
    if presentes:
        jeton.notes.append("Revendications Microsoft Entra : " + ", ".join(presentes) + ".")

    return jeton
