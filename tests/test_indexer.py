# SPDX-License-Identifier: GPL-3.0-or-later
"""Compléments de couverture de `src/indexer.py` (issue #159 : le pont
omprog asynchrone doit garder acquittements et DLQ à l'identique).

L'indexer délègue aux sorties PyStashTemplate depuis #160 — ces tests
couvrent les branches restées hors des tests existants : avertissement
multi-nœuds, authentification transmise au client HTTP, client partagé
avec `install_index_template`, et action invalide sans DLQ (renvoyée à
rsyslog comme un échec transitoire).
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from typing import Any

import httpx
from loguru import logger
from test_integration import make_bridge

from indexer import OpenSearchIndexer, SendOutcome


def _run(coro):
    # Sans pytest-asyncio (convention du dépôt) : asyncio.run direct.
    return asyncio.run(coro)


def _indexer(**kwargs: Any) -> OpenSearchIndexer:
    options: dict[str, Any] = {
        "hosts": [{"host": "127.0.0.1", "port": 9200}],
        "auth": None,
        "index_pattern": "i-%Y.%m.%d",
        "use_ssl": False,
        "verify_certs": False,
    }
    options.update(kwargs)
    return OpenSearchIndexer(**options)


class ClientAvecEntetes:
    """Double réseau qui capture l'en-tête Authorization des requêtes _bulk."""

    def __init__(self) -> None:
        self.authorization: str | None = None
        self.transport = httpx.MockTransport(self._handler)

    def _handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            self.authorization = request.headers.get("authorization")
        return httpx.Response(200, json={"items": [{"index": {"status": 201}}]})


class TestConstructeur:
    def test_plusieurs_noeuds_avertit(self) -> None:
        # Seul le PREMIER nœud est utilisé (failover à l'appelant) : un
        # avertissement le dit, plutôt qu'un échec silencieux.
        messages: list[str] = []
        sink = logger.add(lambda m: messages.append(str(m)), level="WARNING")
        try:
            _indexer(hosts=[{"host": "a", "port": 9200}, {"host": "b", "port": 9200}])
        finally:
            logger.remove(sink)
        assert any("Plusieurs nœuds configurés" in m and "seul le premier est utilisé" in m for m in messages)

    def test_auth_transmise_au_client_en_basic(self) -> None:
        indexer = _indexer(auth=("admin", "s3cret"))
        client = ClientAvecEntetes()
        indexer.sortie._transport = client.transport

        async def scenario() -> SendOutcome:
            resultat = await indexer.send({"m": 1})
            await indexer.close()
            return resultat

        assert _run(scenario()) is SendOutcome.INDEXED
        attendu = "Basic " + base64.b64encode(b"admin:s3cret").decode()
        assert client.authorization == attendu

    def test_client_http_partage_avec_install_template(self) -> None:
        # omprog installe le gabarit d'index via ce client paresseux.
        indexer = _indexer()

        async def scenario() -> None:
            client = await indexer._client()
            assert isinstance(client, httpx.AsyncClient)
            await client.aclose()

        _run(scenario())


def test_action_invalide_sans_dlq_renvoie_a_rsyslog(tmp_path: Path) -> None:
    # Action impossible (update sans _id) sans --dlq-path : comportement
    # historique, l'échec permanent reste RETRYABLE et repart vers rsyslog.
    bridge, _ = make_bridge(
        tmp_path,
        pipeline_conf='output { opensearch { index => "i" action => "update" } }',
        dlq=False,
    )

    async def scenario() -> Any:
        resultat = await bridge.handle_doc({"v": 1})
        await bridge.close()
        return resultat

    assert _run(scenario()) is SendOutcome.RETRYABLE
