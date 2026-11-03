# SPDX-License-Identifier: GPL-3.0-or-later
"""Test d'intégration bout en bout (issue #30) : ligne rsyslog → omprog
(Bridge) → filters → enrichment → pipeline → indexer → serveur OpenSearch factice.

Seul le SERVEUR OpenSearch (réseau) est substitué : `build_parser`,
`build_bridge`, `FilterPipeline`, enrichisseurs, `PipelineInterpreter`,
`OpenSearchIndexer` (fingerprint, DLQ) sont les composants réels —
l'indexer délègue à la sortie `OpenSearchOutput` de PyStashTemplate
(issue #160), substituée par un `httpx.MockTransport` (couture de test
de la sortie, même rôle que l'ancien `FakeOpenSearchClient`). Valide :

- le flux nominal (ligne JSON → filtres → enrichissement → indexation) ;
- le drop par filtre (acquittement « OK », rien d'indexé) ;
- le JSON invalide → DLQ + acquittement (pas de boucle rsyslog) ;
- l'erreur 4xx permanente → DLQ + « OK » (décision définitive, issue #13) ;
- l'erreur transitoire → « Erreur : ... » (rsyslog retient et renvoie) ;
- l'idempotence du fingerprint en ré-émission (même `_id`) ;
- le pipeline `.conf` avec `output{}` (surcharge d'index) ;
- un débit minimal (200 messages, garde-fou de non-régression grossière).

Un client httpx est lié à sa boucle d'événements : chaque scénario tient
dans UN SEUL `asyncio.run` (envois ET fermeture du pont).
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from loguru import logger

from indexer import OpenSearchIndexer, SendOutcome
from omprog import ACK_OK, ACK_RETRY, build_bridge, build_parser, health_check_loop


class FauxOpenSearch:
    """Double du serveur OpenSearch : enregistre ou échoue selon `mode`.

    Modes : "ok" (enregistre l'appel `_bulk`), "4xx" (400 — erreur
    permanente, ex. mapping), "transient" (500 — échec transitoire).
    Reconstruit les tuples (index, document, _id) de l'ancien
    `FakeOpenSearchClient` en décodant le NDJSON reçu.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str | None, dict[str, Any], str | None]] = []
        self.mode = "ok"
        self.health_checks = 0
        self.transport = httpx.MockTransport(self._handler)

    def brancher(self, indexer: OpenSearchIndexer) -> None:
        """Branche ce faux serveur sur la sortie de l'indexer (seul substitut : le réseau)."""
        indexer.sortie._transport = self.transport

    def _handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            # GET / : health check (issue #37).
            self.health_checks += 1
            if self.mode == "transient":
                return httpx.Response(500)
            return httpx.Response(200, json={"version": {"number": "2.19.0-test"}})
        # POST /_bulk : ligne d'action NDJSON + document.
        lignes = [json.loads(ligne) for ligne in request.content.decode().splitlines() if ligne]
        actions: list[str] = []
        for i in range(0, len(lignes), 2):
            ((action, meta),) = lignes[i].items()
            actions.append(action)
            doc = lignes[i + 1] if action != "delete" and i + 1 < len(lignes) else {}
            self.calls.append((meta.get("_index"), doc, meta.get("_id")))
        if self.mode == "4xx":
            return httpx.Response(400, json={"error": {"type": "parse_exception"}})
        if self.mode == "transient":
            return httpx.Response(500)
        return httpx.Response(200, json={"items": [{a: {"status": 201}} for a in actions]})


def make_bridge(
    tmp_path: Path,
    *,
    filters: list[dict[str, Any]] | None = None,
    enrich_dict: dict[str, Any] | None = None,
    fingerprint: str | None = None,
    pipeline_conf: str | None = None,
    dlq: bool = True,
) -> tuple[Any, FauxOpenSearch]:
    """Passe par les VRAIS build_parser/build_bridge (options CLI réelles),
    puis substitue uniquement le serveur réseau de la sortie."""
    argv = ["--opensearch-host", "https://localhost:9200", "--no-verify-certs", "--log-level", "ERROR"]
    if filters is not None:
        p = tmp_path / "filters.json"
        p.write_text(json.dumps(filters), encoding="utf-8")
        argv += ["--filters", str(p)]
    if enrich_dict is not None:
        p = tmp_path / "enrich.json"
        p.write_text(json.dumps(enrich_dict), encoding="utf-8")
        argv += ["--enrich-dict", str(p)]
    if fingerprint is not None:
        argv += ["--document-id-fingerprint", fingerprint]
    if pipeline_conf is not None:
        p = tmp_path / "pipeline.conf"
        p.write_text(pipeline_conf, encoding="utf-8")
        argv += ["--pipeline-conf", str(p)]
    if dlq:
        argv += ["--dlq-path", str(tmp_path / "dlq.jsonl")]
    args = build_parser().parse_args(argv)
    bridge = build_bridge(args)
    fake = FauxOpenSearch()
    fake.brancher(bridge.indexer)  # seul substitut : le réseau
    return bridge, fake


def _read_dlq(tmp_path: Path) -> list[dict[str, Any]]:
    dlq_file = tmp_path / "dlq.jsonl"
    if not dlq_file.exists():
        return []
    return [json.loads(line) for line in dlq_file.read_text(encoding="utf-8").splitlines() if line.strip()]


class TestFluxNominal:
    def test_ligne_valide_filtree_enrichie_indexee(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(
            tmp_path,
            filters=[
                {
                    "type": "dissect",
                    "source": "message",
                    "pattern": "%{src} %{level} %{msg}",
                    "target": "parsed",
                }
            ],
            enrich_dict={"srv1": {"site": "strasbourg"}},
        )
        line = json.dumps({"hostname": "srv1", "message": "app1 INFO connexion ok"})

        async def scenario() -> str:
            reply = await bridge.handle_line(line)
            await bridge.close()
            return reply

        assert asyncio.run(scenario()) == ACK_OK
        assert len(fake.calls) == 1
        index, body, doc_id = fake.calls[0]
        # Index quotidien selon le motif par défaut.
        assert index.startswith("switch-logs-")
        # Le dissect a extrait, l'enrichisseur a fusionné.
        assert body["parsed"] == {"src": "app1", "level": "INFO", "msg": "connexion ok"}
        assert body["enrichment"] == {"site": "strasbourg"}
        # Sans fingerprint configuré : _id aléatoire (None).
        assert doc_id is None

    def test_drop_par_filtre_acquitte_sans_indexer(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(
            tmp_path,
            filters=[{"type": "drop", "source": "message", "words": ["healthcheck"], "mode": "contains"}],
        )

        async def scenario() -> str:
            reply = await bridge.handle_line(json.dumps({"message": "app1 INFO healthcheck"}))
            await bridge.close()
            return reply

        assert asyncio.run(scenario()) == ACK_OK
        assert fake.calls == []


class TestJsonInvalide:
    def test_json_invalide_vers_dlq_et_acquitte(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path)

        async def scenario() -> str:
            reply = await bridge.handle_line("ceci n'est pas du JSON")
            await bridge.close()
            return reply

        # Acquitté « OK » : renvoyer ne rendrait pas le message lisible.
        assert asyncio.run(scenario()) == ACK_OK
        assert fake.calls == []
        entries = _read_dlq(tmp_path)
        assert len(entries) == 1
        assert entries[0]["@dlq_error"].startswith("JSON invalide")
        assert entries[0]["document"] == {"message": "ceci n'est pas du JSON"}


class TestErreursOpenSearch:
    def test_erreur_4xx_permanente_vers_dlq(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path, fingerprint="hostname")
        fake.mode = "4xx"

        async def scenario() -> str:
            reply = await bridge.handle_line(json.dumps({"hostname": "srv1", "message": "x"}))
            await bridge.close()
            return reply

        # Décision définitive : DLQ + « OK » (pas de renvoi en boucle).
        assert asyncio.run(scenario()) == ACK_OK
        entries = _read_dlq(tmp_path)
        assert len(entries) == 1
        assert entries[0]["@dlq_index"].startswith("switch-logs-")
        assert entries[0]["document"] == {"hostname": "srv1", "message": "x"}

    def test_erreur_4xx_sans_dlq_renvoie_a_rsyslog(self, tmp_path: Path) -> None:
        # Sans --dlq-path : comportement historique, l'échec reste RETRYABLE.
        bridge, fake = make_bridge(tmp_path, dlq=False)
        fake.mode = "4xx"

        async def scenario() -> str:
            reply = await bridge.handle_line(json.dumps({"hostname": "srv1"}))
            await bridge.close()
            return reply

        assert asyncio.run(scenario()) == ACK_RETRY

    def test_erreur_transitoire_renvoie_a_rsyslog(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path)
        fake.mode = "transient"

        async def scenario() -> str:
            reply = await bridge.handle_line(json.dumps({"hostname": "srv1"}))
            await bridge.close()
            return reply

        assert asyncio.run(scenario()) == ACK_RETRY


class TestFingerprintIdempotence:
    def test_reemission_meme_id(self, tmp_path: Path) -> None:
        """Ré-émission après accusé perdu (rsyslog confirmMessages) : le même
        document produit le même `_id` — l'indexation écrase au lieu de dupliquer."""
        bridge, fake = make_bridge(tmp_path, fingerprint="hostname,seq")
        doc = {"hostname": "sw01", "seq": 42, "message": "link down"}
        line = json.dumps(doc)

        async def scenario() -> tuple[str, str]:
            r1 = await bridge.handle_line(line)
            r2 = await bridge.handle_line(line)
            await bridge.close()
            return r1, r2

        assert asyncio.run(scenario()) == (ACK_OK, ACK_OK)
        assert len(fake.calls) == 2
        assert fake.calls[0][2] == fake.calls[1][2]  # même _id
        assert fake.calls[0][2] is not None

    def test_documents_differents_ids_differents(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path, fingerprint="hostname")

        async def scenario() -> None:
            await bridge.handle_line(json.dumps({"hostname": "sw01", "message": "a"}))
            await bridge.handle_line(json.dumps({"hostname": "sw02", "message": "b"}))
            await bridge.close()

        asyncio.run(scenario())
        ids = {call[2] for call in fake.calls}
        assert len(ids) == 2

    @staticmethod
    def _bridge_avec(argv: list[str], tmp_path: Path) -> tuple[Any, FauxOpenSearch]:
        args = build_parser().parse_args(argv)
        bridge = build_bridge(args)
        fake = FauxOpenSearch()
        fake.brancher(bridge.indexer)
        return bridge, fake

    def test_gabarit_seul_genere_l_id(self, tmp_path: Path) -> None:
        """--document-id-template seul : le gabarit %{...} rendu sert de _id."""
        bridge, fake = self._bridge_avec(
            [
                "--opensearch-host",
                "https://localhost:9200",
                "--no-verify-certs",
                "--log-level",
                "ERROR",
                "--dlq-path",
                str(tmp_path / "dlq.jsonl"),
                "--document-id-template",
                "%{hostname}",
            ],
            tmp_path,
        )

        async def scenario() -> None:
            await bridge.handle_line(json.dumps({"hostname": "sw01", "message": "x"}))
            await bridge.close()

        asyncio.run(scenario())
        assert fake.calls[0][2] == "sw01"

    def test_fingerprint_prioritaire_sur_gabarit(self, tmp_path: Path) -> None:
        """Les deux configurés (issue #33) : le fingerprint gagne — jamais
        combinés dans un même _id, mais simultané autorisé."""
        bridge, fake = self._bridge_avec(
            [
                "--opensearch-host",
                "https://localhost:9200",
                "--no-verify-certs",
                "--log-level",
                "ERROR",
                "--dlq-path",
                str(tmp_path / "dlq.jsonl"),
                "--document-id-template",
                "%{hostname}",
                "--document-id-fingerprint",
                "hostname",
            ],
            tmp_path,
        )
        doc = {"hostname": "sw01", "message": "x"}

        async def scenario() -> None:
            await bridge.handle_line(json.dumps(doc))
            await bridge.close()

        asyncio.run(scenario())
        # L'_id est l'empreinte sha256 du champ, pas le gabarit « sw01 ».
        from pystashtemplate.fingerprint import compute_fingerprint

        expected = compute_fingerprint(doc, ["hostname"], "sha256")
        assert fake.calls[0][2] == expected
        assert fake.calls[0][2] != "sw01"

    def test_hmac_via_option_et_via_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Issue #28 : --fingerprint-key OU repli FINGERPRINT_KEY — le _id est
        un HMAC (différent du hash simple, différent par clé)."""
        doc = {"hostname": "sw01", "message": "x"}
        base = [
            "--opensearch-host",
            "https://localhost:9200",
            "--no-verify-certs",
            "--log-level",
            "ERROR",
            "--dlq-path",
            str(tmp_path / "dlq.jsonl"),
            "--document-id-fingerprint",
            "hostname",
        ]

        async def envoyer(argv: list[str]) -> str | None:
            bridge, fake = self._bridge_avec(base + argv, tmp_path)
            await bridge.handle_line(json.dumps(doc))
            await bridge.close()
            return fake.calls[0][2]

        async def scenario() -> tuple[str | None, str | None, str | None]:
            with_option = await envoyer(["--fingerprint-key", "cle-option"])
            monkeypatch.setenv("FINGERPRINT_KEY", "cle-env")
            with_env = await envoyer([])
            monkeypatch.delenv("FINGERPRINT_KEY")
            sans_cle = await envoyer([])
            return with_option, with_env, sans_cle

        with_option, with_env, sans_cle = asyncio.run(scenario())

        from pystashtemplate.fingerprint import compute_fingerprint

        assert with_option == compute_fingerprint(doc, ["hostname"], "sha256", key="cle-option")
        assert with_env == compute_fingerprint(doc, ["hostname"], "sha256", key="cle-env")
        assert sans_cle == compute_fingerprint(doc, ["hostname"], "sha256")
        assert len({with_option, with_env, sans_cle}) == 3

    def test_murmur3_via_cli(self, tmp_path: Path) -> None:
        """Issue #28 : --fingerprint-method murmur3 → _id entier décimal."""
        bridge, fake = self._bridge_avec(
            [
                "--opensearch-host",
                "https://localhost:9200",
                "--no-verify-certs",
                "--log-level",
                "ERROR",
                "--dlq-path",
                str(tmp_path / "dlq.jsonl"),
                "--document-id-fingerprint",
                "hostname",
                "--fingerprint-method",
                "murmur3",
            ],
            tmp_path,
        )

        async def scenario() -> None:
            await bridge.handle_line(json.dumps({"hostname": "sw01", "message": "x"}))
            await bridge.close()

        asyncio.run(scenario())
        doc_id = fake.calls[0][2]
        assert doc_id is not None and doc_id.isdigit()


class TestPipelineConf:
    def test_output_conf_surcharge_index(self, tmp_path: Path) -> None:
        conf = """
        filter {
            dissect { mapping => { "message" => "%{src} %{msg}" } }
        }
        output {
            opensearch { index => "logs-test-%{src}" }
        }
        """
        bridge, fake = make_bridge(tmp_path, pipeline_conf=conf)

        async def scenario() -> str:
            reply = await bridge.handle_line(json.dumps({"message": "app1 connexion"}))
            await bridge.close()
            return reply

        assert asyncio.run(scenario()) == ACK_OK
        assert len(fake.calls) == 1
        index, body, _ = fake.calls[0]
        # L'index vient du output{} rendu, pas du motif quotidien.
        assert index == "logs-test-app1"
        assert body["src"] == "app1"


    def test_clone_deux_evenements_indexes(self, tmp_path: Path) -> None:
        """#141 : un `clone` produit l'original ET la copie, tous deux indexés.

        Le second événement réussit alors que le premier aussi : le résultat
        conservé reste la première réussite (branche de garde de `handle_doc`).
        """
        conf = """
        filter {
            clone { clones => ["copie"] }
        }
        """
        bridge, fake = make_bridge(tmp_path, pipeline_conf=conf)

        async def scenario() -> str:
            reply = await bridge.handle_line(json.dumps({"message": "x"}))
            await bridge.close()
            return reply

        assert asyncio.run(scenario()) == ACK_OK
        assert len(fake.calls) == 2


class TestDebitMinimal:
    def test_200_messages_sous_la_seconde(self, tmp_path: Path) -> None:
        """Garde-fou grossier : 200 messages traités en moins d'une seconde
        (aucun verrou de performance : détecte une régression massive du flux)."""
        bridge, fake = make_bridge(tmp_path, fingerprint="seq")
        lines = [json.dumps({"seq": i, "message": f"event {i}"}) for i in range(200)]

        async def scenario() -> None:
            for line in lines:
                reply = await bridge.handle_line(line)
                assert reply == ACK_OK
            await bridge.close()

        start = time.monotonic()
        asyncio.run(scenario())
        elapsed = time.monotonic() - start
        assert len(fake.calls) == 200
        assert len({call[2] for call in fake.calls}) == 200  # _id uniques par champ
        assert elapsed < 1.0, f"débit trop faible : {elapsed:.2f}s pour 200 messages"


# ----------------------------------------------------------------------
# Issue #160 : la sortie PyStashTemplate n'utilise que le PREMIER nœud.
# Le failover transport (opensearch-py, issue #37) disparaît avec le
# client : un nœud mort rend le message à rsyslog (RETRYABLE), qui le
# retient et le renvoie — la retenue rsyslog reste le mécanisme de repli.
# ----------------------------------------------------------------------


class TestNoeudMort:
    def test_renvoie_a_rsyslog(self) -> None:
        """Port 1 fermé (nœud mort) : RETRYABLE, pas d'exception — rsyslog retient."""

        async def scenario() -> SendOutcome:
            indexer = OpenSearchIndexer(
                hosts=[{"host": "127.0.0.1", "port": 1}],
                auth=None,
                index_pattern="switch-logs-%Y.%m.%d",
                use_ssl=False,
                verify_certs=False,
            )
            try:
                return await indexer.send({"a": 1})
            finally:
                await indexer.close()

        assert asyncio.run(scenario()) is SendOutcome.RETRYABLE


class TestOptionsIndexer:
    """Options du connecteur traduites en options de sortie (#160), parité vérifiée."""

    @staticmethod
    def _indexer(auth: tuple[str, str] | None = None, **kwargs: Any) -> OpenSearchIndexer:
        return OpenSearchIndexer(
            hosts=[{"host": "127.0.0.1", "port": 9200}],
            auth=auth,
            index_pattern="switch-logs-%Y.%m.%d",
            use_ssl=False,
            verify_certs=False,
            **kwargs,
        )

    def test_plusieurs_noeuds_avertit(self) -> None:
        """La sortie n'utilise que le premier nœud : l'avertissement part au démarrage."""
        messages: list[str] = []
        sink = logger.add(lambda m: messages.append(m.record["message"]), level="WARNING")
        try:
            indexer = OpenSearchIndexer(
                hosts=[{"host": "127.0.0.1", "port": 9200}, {"host": "127.0.0.1", "port": 9201}],
                auth=None,
                index_pattern="switch-logs-%Y.%m.%d",
                use_ssl=False,
                verify_certs=False,
            )
            asyncio.run(indexer.close())
        finally:
            logger.remove(sink)
        assert any("seul le premier est utilisé" in message for message in messages)

    def test_auth_transmis_a_la_sortie(self) -> None:
        """`auth` du connecteur devient `user`/`password` de la sortie."""

        async def scenario() -> dict[str, Any]:
            indexer = self._indexer(auth=("u", "p"))
            try:
                return dict(indexer.sortie.options)
            finally:
                await indexer.close()

        options = asyncio.run(scenario())
        assert (options["user"], options["password"]) == ("u", "p")

    def test_client_partage_avec_la_sortie(self) -> None:
        """La couture `_client()` d'omprog renvoie LE client httpx de la sortie."""

        async def scenario() -> bool:
            indexer = self._indexer()
            try:
                client = await indexer._client()
                return client is indexer.sortie._client_http()
            finally:
                await indexer.close()

        assert asyncio.run(scenario())

    def test_action_invalide_sans_dlq_renvoie_retryable(self) -> None:
        """Comportement historique sans DLQ : l'échec permanent reste RETRYABLE."""

        async def scenario() -> SendOutcome:
            indexer = self._indexer()
            try:
                return await indexer.send({"v": 1}, action="upsert")
            finally:
                await indexer.close()

        assert asyncio.run(scenario()) is SendOutcome.RETRYABLE


class TestHealthCheckPeriodique:
    def test_health_renvoie_la_version(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path)

        async def scenario() -> dict[str, Any]:
            info = await bridge.indexer.health()
            await bridge.close()
            return info

        assert asyncio.run(scenario())["version"]["number"] == "2.19.0-test"
        assert fake.health_checks == 1

    def test_health_echec_leve(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path)
        fake.mode = "transient"

        async def scenario() -> None:
            with pytest.raises(httpx.HTTPStatusError):
                await bridge.indexer.health()
            await bridge.close()

        asyncio.run(scenario())

    def test_boucle_s_arrete_avec_stop_et_surveille(self, tmp_path: Path) -> None:
        """La boucle tourne tant que `stop` n'est pas demandé, sans jamais lever."""
        bridge, fake = make_bridge(tmp_path)

        async def scenario() -> None:
            stop = asyncio.Event()
            loop_task = asyncio.ensure_future(health_check_loop(bridge, interval=0.01, stop=stop))
            # Laisse la boucle tourner, puis demande l'arrêt.
            await asyncio.sleep(0.05)
            stop.set()
            await loop_task  # la boucle se termine proprement, sans exception
            await bridge.close()

        asyncio.run(scenario())
        assert fake.health_checks >= 1

    def test_option_cli_defaut_300_et_desactivable(self) -> None:
        parser = build_parser()
        args = parser.parse_args([])
        assert args.health_check_interval == 300
        args_off = parser.parse_args(["--health-check-interval", "0"])
        assert args_off.health_check_interval == 0
