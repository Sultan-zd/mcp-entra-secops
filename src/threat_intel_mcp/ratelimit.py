"""Limitation de débit — désormais portée par le socle partagé.

Le mécanisme est identique pour toutes les sources publiques qu'ARGUS
interroge : ce module ne fait plus que réexporter, pour ne pas casser les
imports existants ni leurs tests.
"""

from __future__ import annotations

from argus_net.ratelimit import QuotaExceededError, RateLimiterRegistry, TokenBucket

__all__ = ["QuotaExceededError", "RateLimiterRegistry", "TokenBucket"]
