"""Conservation des investigations.

Deux exigences se rejoignent ici. La console a besoin des dossiers récents pour
les afficher ; la conformité a besoin qu'aucun ne disparaisse. D'où deux
couches : un anneau en mémoire pour l'affichage, et un journal en ajout seul
pour l'audit.

Le journal est en **ajout seul** à dessein : une trace qu'on peut réécrire ne
prouve rien.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path

from argus_agent.models import Alert, TriageVerdict

from .models import ApprovalRecord, RunRecord

logger = logging.getLogger(__name__)


def new_run_id() -> str:
    """Identifiant lisible et triable : la date, puis un suffixe court."""
    return f"{datetime.now(UTC):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"


class RunStore:
    """Anneau en mémoire, doublé d'un journal en ajout seul."""

    def __init__(self, capacity: int = 200, journal: Path | None = None) -> None:
        self._runs: deque[RunRecord] = deque(maxlen=capacity)
        self._index: dict[str, RunRecord] = {}
        self._journal = journal
        # La console sert plusieurs requêtes en parallèle : sans verrou, une
        # lecture pourrait tomber sur un index à moitié mis à jour.
        self._verrou = threading.Lock()

        if journal is not None:
            journal.parent.mkdir(parents=True, exist_ok=True)

    def record(self, alert: Alert, verdict: TriageVerdict) -> RunRecord:
        """Archive une investigation et retourne son dossier."""
        dossier = RunRecord(run_id=new_run_id(), alert=alert, verdict=verdict)

        with self._verrou:
            if len(self._runs) == self._runs.maxlen:
                # L'anneau évince le plus ancien : on retire aussi son entrée
                # d'index, sinon la mémoire enfle sans limite.
                self._index.pop(self._runs[0].run_id, None)
            self._runs.append(dossier)
            self._index[dossier.run_id] = dossier

        self._append(dossier)
        return dossier

    def approve(
        self, run_id: str, action: str, decision: str, approver: str, note: str | None = None
    ) -> ApprovalRecord:
        """Consigne une décision humaine sur une action proposée.

        Rien n'est exécuté : la plateforme enregistre qui a décidé quoi et
        quand. L'exécution reste un geste distinct, hors de sa portée.
        """
        dossier = self.get(run_id)
        if dossier is None:
            raise KeyError(f"Dossier inconnu : {run_id}")

        connues = {a.action for a in dossier.verdict.recommended_actions}
        if action not in connues:
            raise ValueError(
                f"L'action « {action} » n'a pas été proposée sur ce dossier. "
                "Approuver une action non proposée n'aurait aucune trace d'origine."
            )
        if decision not in {"approved", "rejected"}:
            raise ValueError("La décision doit être « approved » ou « rejected ».")

        trace = ApprovalRecord(action=action, decision=decision, approver=approver, note=note)
        with self._verrou:
            dossier.approvals.append(trace)
        self._append(dossier, kind="approval")
        return trace

    def get(self, run_id: str) -> RunRecord | None:
        with self._verrou:
            return self._index.get(run_id)

    def recent(self, limit: int = 25) -> list[RunRecord]:
        with self._verrou:
            return list(self._runs)[-limit:][::-1]

    def summary(self) -> dict[str, object]:
        """Chiffres d'ensemble, pour l'en-tête de la console."""
        with self._verrou:
            dossiers = list(self._runs)

        if not dossiers:
            return {
                "runs": 0,
                "malicious": 0,
                "escalated": 0,
                "pending_actions": 0,
                "external_calls": 0,
                "cache_ratio": 0.0,
                "median_duration_ms": 0,
            }

        durees = sorted(d.verdict.duration_ms for d in dossiers)
        externes = sum(d.costs.total_external for d in dossiers)
        caches = sum(d.costs.cache_hits for d in dossiers)

        return {
            "runs": len(dossiers),
            "malicious": sum(1 for d in dossiers if d.verdict.verdict == "malicious"),
            "escalated": sum(1 for d in dossiers if d.verdict.escalate_to_human),
            "pending_actions": sum(d.pending_actions for d in dossiers),
            "external_calls": externes,
            "cache_ratio": round(caches / (externes + caches), 3) if externes + caches else 0.0,
            "median_duration_ms": durees[len(durees) // 2],
        }

    def _append(self, dossier: RunRecord, kind: str = "run") -> None:
        """Écrit une ligne dans le journal d'audit.

        Une panne d'écriture ne doit jamais faire perdre un verdict déjà rendu :
        l'erreur est tracée, et l'investigation suit son cours.
        """
        if self._journal is None:
            return
        ligne = {
            "at": datetime.now(UTC).isoformat(),
            "kind": kind,
            "run": dossier.model_dump(mode="json"),
        }
        try:
            with self._journal.open("a", encoding="utf-8") as fichier:
                fichier.write(json.dumps(ligne, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("Journal d'audit non écrit (%s) : %s", self._journal, exc)
