"""Console analyste : l'interface où l'investigation devient visible.

Le choix central est le **flux d'événements serveur** : chaque étape de l'agent
part vers le navigateur au moment où elle se termine, plutôt qu'un sablier
suivi d'un verdict. Un agent opaque n'est pas adopté — on ne fait pas confiance
à ce qu'on ne voit pas se produire.

La porte d'approbation vit ici aussi. Elle **consigne** une décision humaine ;
elle n'exécute rien. La distinction est délibérée : tant que la plateforme ne
détient aucun droit d'écriture sur le tenant, une erreur de l'agent ne peut pas
se traduire en incident.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from argus_agent.models import Alert, TriageStep
from argus_agent.orchestrator import run_triage
from argus_obs.store import RunStore
from email_security_mcp.config import get_settings as mail_settings
from email_security_mcp.runtime import build_resolver as build_dns
from entra_secops_mcp.runtime import lifespan as entra_lifespan
from threat_intel_mcp.runtime import lifespan as ti_lifespan

logger = logging.getLogger(__name__)

STATIC = Path(__file__).parent / "static"

#: Journal d'audit en ajout seul. Une trace réinscriptible ne prouve rien.
JOURNAL = Path("data/audit.jsonl")

store = RunStore(journal=JOURNAL)


class ApprovalRequest(BaseModel):
    """Décision humaine sur une action proposée."""

    action: str = Field(description="Action concernée.")
    decision: str = Field(description="approved ou rejected.")
    approver: str = Field(min_length=1, description="Identité de la personne qui décide.")
    note: str | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Ouvre les trois serveurs d'outils pour la durée de vie de la console."""
    import email_security_mcp.runtime as mail_runtime

    async with entra_lifespan(None), ti_lifespan(None):
        # Le résolveur DNS n'a pas de ressource à libérer : on l'installe
        # directement plutôt que d'imbriquer un troisième gestionnaire.
        mail_runtime._resolver = build_dns(mail_settings())
        try:
            yield
        finally:
            mail_runtime._resolver = None


app = FastAPI(title="ARGUS — console analyste", lifespan=lifespan)


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/summary")
async def summary() -> dict[str, Any]:
    """Chiffres d'ensemble affichés en tête de console."""
    return dict(store.summary())


@app.get("/api/runs")
async def runs(limit: int = 25) -> list[dict[str, Any]]:
    """Dossiers récents, du plus récent au plus ancien."""
    return [
        {
            "run_id": d.run_id,
            "started_at": d.started_at.isoformat(),
            "upn": d.alert.upn,
            "kind": d.alert.kind,
            "verdict": d.verdict.verdict,
            "severity": d.verdict.severity,
            "escalate": d.verdict.escalate_to_human,
            "pending_actions": d.pending_actions,
            "duration_ms": d.verdict.duration_ms,
        }
        for d in store.recent(limit)
    ]


@app.get("/api/runs/{run_id}")
async def run_detail(run_id: str) -> dict[str, Any]:
    """Dossier complet : trace, verdict, coûts, approbations."""
    dossier = store.get(run_id)
    if dossier is None:
        raise HTTPException(status_code=404, detail=f"Dossier inconnu : {run_id}")
    return dossier.model_dump(mode="json")


@app.post("/api/runs/{run_id}/approvals")
async def approve(run_id: str, requete: ApprovalRequest) -> dict[str, Any]:
    """Consigne une décision humaine. **N'exécute rien.**"""
    try:
        trace = store.approve(
            run_id, requete.action, requete.decision, requete.approver, requete.note
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "recorded": trace.model_dump(mode="json"),
        "executed": False,
        "note": (
            "La décision est consignée dans le journal d'audit. Aucune action n'a été "
            "exécutée sur le tenant : la plateforme ne détient aucun droit d'écriture."
        ),
    }


@app.post("/api/investigate")
async def investigate(alert: Alert) -> StreamingResponse:
    """Lance une investigation et diffuse chaque étape au fil de l'eau.

    Un flux d'événements serveur suffit : la communication est unidirectionnelle,
    du serveur vers le navigateur. Une WebSocket serait surdimensionnée.
    """
    file: asyncio.Queue[str | None] = asyncio.Queue()

    def sur_etape(etape: TriageStep) -> None:
        file.put_nowait("event: step\ndata: " + etape.model_dump_json() + "\n\n")

    async def mener() -> None:
        try:
            verdict = await run_triage(alert, on_step=sur_etape)
            dossier = store.record(alert, verdict)
            charge = {
                "run_id": dossier.run_id,
                "verdict": verdict.model_dump(mode="json"),
            }
            await file.put(
                "event: verdict\ndata: " + json.dumps(charge, ensure_ascii=False) + "\n\n"
            )
        except Exception as exc:
            # Une investigation qui échoue doit le dire au navigateur, pas
            # laisser le flux ouvert sur un sablier éternel.
            logger.exception("Investigation en échec.")
            message = json.dumps({"error": f"{type(exc).__name__} : {exc}"}, ensure_ascii=False)
            await file.put("event: error\ndata: " + message + "\n\n")
        finally:
            await file.put(None)

    async def flux() -> AsyncIterator[str]:
        tache = asyncio.create_task(mener())
        try:
            while True:
                morceau = await file.get()
                if morceau is None:
                    break
                yield morceau
        finally:
            # Un navigateur qui ferme l'onglet ne doit pas laisser une
            # investigation tourner indéfiniment côté serveur.
            if not tache.done():
                tache.cancel()

    return StreamingResponse(
        flux(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
