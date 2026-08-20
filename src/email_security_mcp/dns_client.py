"""Résolution DNS : SPF, DKIM et DMARC sont tous publiés dans le DNS.

Deux implémentations partagent la même interface. Le mode fixture permet de
tester une posture de messagerie sans dépendre d'un domaine réel — et surtout
sans que les tests dépendent de ce qu'une organisation tierce publie ce jour-là.
"""

from __future__ import annotations

import abc
import json
import logging
from importlib import resources
from typing import Any

logger = logging.getLogger(__name__)


class DnsUnavailableError(RuntimeError):
    """La résolution a échoué pour une raison technique, pas par absence d'enregistrement.

    La distinction est essentielle : un domaine sans enregistrement SPF est un
    constat de sécurité, une panne DNS n'en est pas un. Les confondre ferait
    conclure à tort qu'un domaine est mal protégé.
    """


class DnsResolver(abc.ABC):
    """Interface minimale : seuls TXT et MX sont nécessaires ici."""

    @abc.abstractmethod
    async def txt(self, name: str) -> list[str]:
        """Enregistrements TXT, chaînes déjà concaténées."""

    @abc.abstractmethod
    async def mx(self, name: str) -> list[str]:
        """Noms des serveurs de messagerie déclarés."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Libère les ressources détenues."""


class LiveDnsResolver(DnsResolver):
    """Résolution réelle, via dnspython en asynchrone."""

    def __init__(self, timeout: float, nameservers: list[str] | None = None) -> None:
        import dns.asyncresolver

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers

    async def _query(self, name: str, rdtype: str) -> list[Any]:
        import dns.resolver

        try:
            reponse = await self._resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Absence d'enregistrement : c'est une réponse, pas une panne.
            return []
        except dns.resolver.NoNameservers as exc:
            raise DnsUnavailableError(f"Aucun serveur DNS n'a répondu pour « {name} ».") from exc
        except Exception as exc:
            raise DnsUnavailableError(
                f"Résolution DNS impossible pour « {name} » : {type(exc).__name__}."
            ) from exc
        return list(reponse)

    async def txt(self, name: str) -> list[str]:
        enregistrements = await self._query(name, "TXT")
        # Un TXT long est découpé en segments de 255 octets : la norme impose
        # de les concaténer sans séparateur avant toute interprétation.
        return [
            b"".join(segment for segment in rdata.strings).decode("utf-8", errors="replace")
            for rdata in enregistrements
        ]

    async def mx(self, name: str) -> list[str]:
        return [str(rdata.exchange).rstrip(".") for rdata in await self._query(name, "MX")]

    async def aclose(self) -> None:
        """dnspython ne detient aucune ressource persistante a liberer."""
        return None


class FixtureDnsResolver(DnsResolver):
    """Rejoue des zones DNS enregistrées, pour des tests reproductibles."""

    def __init__(self, zones: dict[str, dict[str, list[str]]] | None = None) -> None:
        if zones is None:
            source = resources.files("email_security_mcp.fixtures").joinpath("dns.json")
            zones = json.loads(source.read_text(encoding="utf-8"))["zones"]
        self._zones = {nom.lower(): contenu for nom, contenu in zones.items()}

    async def txt(self, name: str) -> list[str]:
        return list(self._zones.get(name.lower().rstrip("."), {}).get("TXT", []))

    async def mx(self, name: str) -> list[str]:
        return list(self._zones.get(name.lower().rstrip("."), {}).get("MX", []))

    async def aclose(self) -> None:
        """Aucune ressource : les zones sont lues en memoire."""
        return None


class CountingDnsResolver(DnsResolver):
    """Décorateur qui compte les résolutions effectuées.

    C'est l'instrument central de l'analyse SPF : la norme plafonne à dix le
    nombre de résolutions déclenchées par l'évaluation d'un enregistrement.
    Au-delà, SPF échoue en `permerror` et **cesse silencieusement de protéger
    le domaine**. Sans compteur, cette panne est invisible.
    """

    def __init__(self, inner: DnsResolver) -> None:
        self._inner = inner
        self.lookups = 0
        self.void_lookups = 0

    async def txt(self, name: str) -> list[str]:
        self.lookups += 1
        resultat = await self._inner.txt(name)
        if not resultat:
            self.void_lookups += 1
        return resultat

    async def mx(self, name: str) -> list[str]:
        self.lookups += 1
        resultat = await self._inner.mx(name)
        if not resultat:
            self.void_lookups += 1
        return resultat

    async def aclose(self) -> None:
        await self._inner.aclose()
