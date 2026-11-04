# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #126 : `action`, `pipeline` et `routing` des sorties opensearch d'un `.conf`.

Issue #160 : l'envoi passe par la sortie `OpenSearchOutput` de
PyStashTemplate (API `_bulk`, NDJSON) — le double reconstruit les appels
façon client historique (méthode + arguments) en décodant le NDJSON et
les paramètres de requête, pour garder les assertions d'avant la
migration. Changement documenté : `pipeline` est désormais transmis
AUSI pour `update`/`delete` (l'ancien client l'ignorait silencieusement).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pystashtemplate.indexer import ACTIONS, SendOutcome
from test_integration import _read_dlq, make_bridge

from omprog import _options_envoi


class ClientActions:
    """Double du serveur OpenSearch qui enregistre chaque envoi (méthode, arguments).

    Décode le NDJSON `_bulk` (ligne d'action + document) et les
    paramètres de requête (`pipeline`), et les remet en forme comme les
    appels du client opensearch-py historique (`index`/`update`/`delete`).
    `erreur_http` (statut) simule une réponse en erreur du serveur.
    """

    def __init__(self, erreur_http: int | None = None) -> None:
        self.appels: list[tuple[str, dict[str, Any]]] = []
        self.erreur_http = erreur_http
        self.transport = httpx.MockTransport(self._handler)

    def brancher(self, indexer: Any) -> None:
        """Branche ce double sur la sortie de l'indexer (couture de test)."""
        indexer.sortie._transport = self.transport

    def _handler(self, request: httpx.Request) -> httpx.Response:
        pipeline = request.url.params.get("pipeline")
        lignes = [json.loads(ligne) for ligne in request.content.decode().splitlines() if ligne]
        actions_reponse: list[str] = []
        i = 0
        while i < len(lignes):
            ((action, meta),) = lignes[i].items()
            actions_reponse.append(action)
            kwargs: dict[str, Any] = {"index": meta.get("_index")}
            if meta.get("_id"):
                kwargs["id"] = meta["_id"]
            if meta.get("routing"):
                kwargs["routing"] = meta["routing"]
            if action == "update":
                corps: dict[str, Any] = lignes[i + 1]
                kwargs["body"] = corps
                if pipeline:
                    kwargs["pipeline"] = pipeline
                i += 2
            else:
                if action == "delete":
                    if pipeline:
                        kwargs["pipeline"] = pipeline
                else:
                    if pipeline:
                        kwargs["pipeline"] = pipeline
                    if action == "create":
                        # L'API _bulk encode « create » comme action ; le
                        # client historique appelait index(op_type=create).
                        action = "index"
                        kwargs["op_type"] = "create"
                    kwargs["body"] = lignes[i + 1]
                    kwargs.setdefault("id", None)
                i += 2 if action != "delete" else 1
            self.appels.append((action, kwargs))
        if self.erreur_http is not None:
            return httpx.Response(self.erreur_http, json={"error": {"type": "simulation"}})
        return httpx.Response(200, json={"items": [{a: {"status": 201}} for a in actions_reponse]})


def _envoyer(tmp_path: Path, sortie: str, doc: dict[str, Any], client: ClientActions | None = None) -> Any:
    bridge, _ = make_bridge(tmp_path, pipeline_conf=f'output {{ opensearch {{ index => "i" {sortie} }} }}')
    client = client or ClientActions()
    client.brancher(bridge.indexer)

    async def scenario() -> Any:
        resultat = await bridge.handle_doc(doc)
        await bridge.close()
        return resultat

    return asyncio.run(scenario()), client.appels


def test_index_par_defaut_sans_parametres_en_plus(tmp_path: Path) -> None:
    resultat, appels = _envoyer(tmp_path, "", {"a": 1})
    assert resultat is SendOutcome.INDEXED
    assert appels == [("index", {"index": "i", "body": {"a": 1}, "id": None})]


def test_create_pipeline_routing_en_gabarits(tmp_path: Path) -> None:
    sortie = 'action => "%{op}" pipeline => "p-%{t}" routing => "%{u}"'
    _, appels = _envoyer(tmp_path, sortie, {"op": "create", "t": "x", "u": "42"})
    assert appels == [
        (
            "index",
            {
                "index": "i",
                "body": {"op": "create", "t": "x", "u": "42"},
                "id": None,
                "pipeline": "p-x",
                "routing": "42",
                "op_type": "create",
            },
        )
    ]


def test_update_doc_as_upsert_et_pipeline_transmis(tmp_path: Path) -> None:
    """Changement documenté (#160) : `pipeline` est transmis aussi pour
    `update` (l'ancien client l'ignorait silencieusement)."""
    sortie = 'action => "update" document_id => "%{id}" doc_as_upsert => true routing => "r" pipeline => "p"'
    _, appels = _envoyer(tmp_path, sortie, {"id": "7"})
    assert appels == [
        (
            "update",
            {
                "index": "i",
                "id": "7",
                "body": {"doc": {"id": "7"}, "doc_as_upsert": True},
                "routing": "r",
                "pipeline": "p",
            },
        )
    ]
    _, appels = _envoyer(tmp_path, 'action => "update" document_id => "7"', {"v": 1})
    assert appels == [("update", {"index": "i", "id": "7", "body": {"doc": {"v": 1}}})]


def test_delete(tmp_path: Path) -> None:
    _, appels = _envoyer(tmp_path, 'action => "delete" document_id => "7"', {"v": 1})
    assert appels == [("delete", {"index": "i", "id": "7"})]


@pytest.mark.parametrize(
    "sortie",
    ['action => "update"', 'action => "delete" document_id => ""', 'action => "upsert"'],
    ids=["update-sans-id", "delete-id-vide", "action-inconnue"],
)
def test_action_invalide_en_dlq(tmp_path: Path, sortie: str) -> None:
    resultat, appels = _envoyer(tmp_path, sortie, {"v": 1})
    assert (resultat, appels) == (SendOutcome.DEAD_LETTERED, [])
    assert len(_read_dlq(tmp_path)) == 1


def test_delete_introuvable_est_permanent(tmp_path: Path) -> None:
    """Un 404 (statut permanent, comme le NotFoundError historique) : DLQ."""
    client = ClientActions(erreur_http=404)
    resultat, _ = _envoyer(tmp_path, 'action => "delete" document_id => "7"', {"v": 1}, client)
    assert resultat is SendOutcome.DEAD_LETTERED


def test_options_envoi() -> None:
    assert ACTIONS == ("index", "create", "update", "delete")
    assert _options_envoi({"index": "i", "action": " ", "doc_as_upsert": "true"}) == {"index": "i", "document_id": None}
