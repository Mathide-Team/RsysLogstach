# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #126 : `action`, `pipeline` et `routing` des sorties opensearch d'un `.conf`."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from opensearchpy.exceptions import NotFoundError
from test_integration import _read_dlq, make_bridge

from indexer import ACTIONS, SendOutcome
from omprog import _options_envoi


class ClientActions:
    """Double d'AsyncOpenSearch qui enregistre chaque appel (méthode, arguments)."""

    def __init__(self, erreur: Exception | None = None) -> None:
        self.appels: list[tuple[str, dict[str, Any]]] = []
        self.erreur = erreur

    async def _appel(self, methode: str, **kwargs: Any) -> None:
        if self.erreur is not None:
            raise self.erreur
        self.appels.append((methode, kwargs))

    async def index(self, **kwargs: Any) -> None:
        await self._appel("index", **kwargs)

    async def update(self, **kwargs: Any) -> None:
        await self._appel("update", **kwargs)

    async def delete(self, **kwargs: Any) -> None:
        await self._appel("delete", **kwargs)

    async def close(self) -> None:
        return None


def _envoyer(tmp_path: Path, sortie: str, doc: dict[str, Any], client: ClientActions | None = None) -> Any:
    bridge, _ = make_bridge(tmp_path, pipeline_conf=f'output {{ opensearch {{ index => "i" {sortie} }} }}')
    client = client or ClientActions()
    bridge.indexer._client = client
    resultat = asyncio.run(bridge.handle_doc(doc))
    return resultat, client.appels


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


def test_update_doc_as_upsert_et_pipeline_ignore(tmp_path: Path) -> None:
    sortie = 'action => "update" document_id => "%{id}" doc_as_upsert => true routing => "r" pipeline => "p"'
    _, appels = _envoyer(tmp_path, sortie, {"id": "7"})
    assert appels == [
        ("update", {"index": "i", "id": "7", "body": {"doc": {"id": "7"}, "doc_as_upsert": True}, "routing": "r"})
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
    client = ClientActions(NotFoundError(404, "not_found", {}))
    resultat, _ = _envoyer(tmp_path, 'action => "delete" document_id => "7"', {"v": 1}, client)
    assert resultat is SendOutcome.DEAD_LETTERED


def test_options_envoi() -> None:
    assert ACTIONS == ("index", "create", "update", "delete")
    assert _options_envoi({"index": "i", "action": " ", "doc_as_upsert": "true"}) == {"index": "i", "document_id": None}
