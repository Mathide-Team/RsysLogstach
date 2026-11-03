# SPDX-License-Identifier: GPL-3.0-or-later
"""Test d'intégration bout en bout (issue #30) : ligne rsyslog → omprog
(Bridge) → filters → enrichment → pipeline → indexer → client OpenSearch factice.

Seul le CLIENT OpenSearch (réseau) est substitué : `build_parser`,
`build_bridge`, `FilterPipeline`, enrichisseurs, `PipelineInterpreter`,
`OpenSearchIndexer` (fingerprint, DLQ) sont les composants réels. Valide :

- le flux nominal (ligne JSON → filtres → enrichissement → indexation) ;
- le drop par filtre (acquittement « OK », rien d'indexé) ;
- le JSON invalide → DLQ + acquittement (pas de boucle rsyslog) ;
- l'erreur 4xx permanente → DLQ + « OK » (décision définitive, issue #13) ;
- l'erreur transitoire → « Erreur : ... » (rsyslog retient et renvoie) ;
- l'idempotence du fingerprint en ré-émission (même `_id`) ;
- le pipeline `.conf` avec `output{}` (surcharge d'index) ;
- un débit minimal (200 messages, garde-fou de non-régression grossière).
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest
from opensearchpy.exceptions import OpenSearchException, RequestError

from indexer import OpenSearchIndexer, SendOutcome
from omprog import ACK_OK, ACK_RETRY, build_bridge, build_parser, health_check_loop


class FakeOpenSearchClient:
    """Double du client AsyncOpenSearch : enregistre ou échoue selon `mode`.

    Modes : "ok" (enregistre l'appel), "4xx" (RequestError — erreur
    permanente de `_PERMANENT_ERRORS`), "transient" (OpenSearchException
    générique — échec transitoire).
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str | None, dict[str, Any], str | None]] = []
        self.mode = "ok"
        self.closed = False
        self.health_checks = 0

    async def index(self, *, index: str, body: dict[str, Any], id: str | None) -> None:
        if self.mode == "4xx":
            raise RequestError(400, "parse_exception", {})
        if self.mode == "transient":
            raise OpenSearchException("connection timeout (test)")
        self.calls.append((index, body, id))

    async def close(self) -> None:
        self.closed = True

    async def info(self) -> dict[str, Any]:
        # Endpoint GET / (health check, issue #37).
        if self.mode == "transient":
            raise OpenSearchException("connection refused (test)")
        self.health_checks += 1
        return {"version": {"number": "2.19.0-test"}}


def make_bridge(
    tmp_path: Path,
    *,
    filters: list[dict[str, Any]] | None = None,
    enrich_dict: dict[str, Any] | None = None,
    fingerprint: str | None = None,
    pipeline_conf: str | None = None,
    dlq: bool = True,
) -> tuple[Any, FakeOpenSearchClient]:
    """Passe par les VRAIS build_parser/build_bridge (options CLI réelles),
    puis substitue uniquement le client réseau de l'indexeur."""
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
    fake = FakeOpenSearchClient()
    bridge.indexer._client = fake  # seul substitut : le réseau
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
        reply = asyncio.run(bridge.handle_line(line))
        asyncio.run(bridge.close())
        assert reply == ACK_OK
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
        reply = asyncio.run(bridge.handle_line(json.dumps({"message": "app1 INFO healthcheck"})))
        asyncio.run(bridge.close())
        assert reply == ACK_OK
        assert fake.calls == []


class TestJsonInvalide:
    def test_json_invalide_vers_dlq_et_acquitte(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path)
        reply = asyncio.run(bridge.handle_line("ceci n'est pas du JSON"))
        asyncio.run(bridge.close())
        # Acquitté « OK » : renvoyer ne rendrait pas le message lisible.
        assert reply == ACK_OK
        assert fake.calls == []
        entries = _read_dlq(tmp_path)
        assert len(entries) == 1
        assert entries[0]["@dlq_error"].startswith("JSON invalide")
        assert entries[0]["document"] == {"message": "ceci n'est pas du JSON"}


class TestErreursOpenSearch:
    def test_erreur_4xx_permanente_vers_dlq(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path, fingerprint="hostname")
        fake.mode = "4xx"
        reply = asyncio.run(bridge.handle_line(json.dumps({"hostname": "srv1", "message": "x"})))
        asyncio.run(bridge.close())
        # Décision définitive : DLQ + « OK » (pas de renvoi en boucle).
        assert reply == ACK_OK
        entries = _read_dlq(tmp_path)
        assert len(entries) == 1
        assert entries[0]["@dlq_index"].startswith("switch-logs-")
        assert entries[0]["document"] == {"hostname": "srv1", "message": "x"}

    def test_erreur_4xx_sans_dlq_renvoie_a_rsyslog(self, tmp_path: Path) -> None:
        # Sans --dlq-path : comportement historique, l'échec reste RETRYABLE.
        bridge, fake = make_bridge(tmp_path, dlq=False)
        fake.mode = "4xx"
        reply = asyncio.run(bridge.handle_line(json.dumps({"hostname": "srv1"})))
        asyncio.run(bridge.close())
        assert reply == ACK_RETRY

    def test_erreur_transitoire_renvoie_a_rsyslog(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path)
        fake.mode = "transient"
        reply = asyncio.run(bridge.handle_line(json.dumps({"hostname": "srv1"})))
        asyncio.run(bridge.close())
        assert reply == ACK_RETRY


class TestFingerprintIdempotence:
    def test_reemission_meme_id(self, tmp_path: Path) -> None:
        """Ré-émission après accusé perdu (rsyslog confirmMessages) : le même
        document produit le même `_id` — l'indexation écrase au lieu de dupliquer."""
        bridge, fake = make_bridge(tmp_path, fingerprint="hostname,seq")
        doc = {"hostname": "sw01", "seq": 42, "message": "link down"}
        line = json.dumps(doc)
        r1 = asyncio.run(bridge.handle_line(line))
        r2 = asyncio.run(bridge.handle_line(line))
        asyncio.run(bridge.close())
        assert (r1, r2) == (ACK_OK, ACK_OK)
        assert len(fake.calls) == 2
        assert fake.calls[0][2] == fake.calls[1][2]  # même _id
        assert fake.calls[0][2] is not None

    def test_documents_differents_ids_differents(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path, fingerprint="hostname")
        asyncio.run(bridge.handle_line(json.dumps({"hostname": "sw01", "message": "a"})))
        asyncio.run(bridge.handle_line(json.dumps({"hostname": "sw02", "message": "b"})))
        asyncio.run(bridge.close())
        ids = {call[2] for call in fake.calls}
        assert len(ids) == 2

    def test_gabarit_seul_genere_l_id(self, tmp_path: Path) -> None:
        """--document-id-template seul : le gabarit %{...} rendu sert de _id."""
        parser_argv = [
            "--opensearch-host",
            "https://localhost:9200",
            "--no-verify-certs",
            "--log-level",
            "ERROR",
            "--dlq-path",
            str(tmp_path / "dlq.jsonl"),
            "--document-id-template",
            "%{hostname}",
        ]
        from omprog import build_bridge, build_parser

        args = build_parser().parse_args(parser_argv)
        bridge = build_bridge(args)
        fake = FakeOpenSearchClient()
        bridge.indexer._client = fake
        asyncio.run(bridge.handle_line(json.dumps({"hostname": "sw01", "message": "x"})))
        asyncio.run(bridge.close())
        assert fake.calls[0][2] == "sw01"

    def test_fingerprint_prioritaire_sur_gabarit(self, tmp_path: Path) -> None:
        """Les deux configurés (issue #33) : le fingerprint gagne — jamais
        combinés dans un même _id, mais simultané autorisé."""
        parser_argv = [
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
        ]
        from omprog import build_bridge, build_parser

        args = build_parser().parse_args(parser_argv)
        bridge = build_bridge(args)
        fake = FakeOpenSearchClient()
        bridge.indexer._client = fake
        doc = {"hostname": "sw01", "message": "x"}
        asyncio.run(bridge.handle_line(json.dumps(doc)))
        asyncio.run(bridge.close())
        # L'_id est l'empreinte sha256 du champ, pas le gabarit « sw01 ».
        from pystashtemplate.fingerprint import compute_fingerprint

        expected = compute_fingerprint(doc, ["hostname"], "sha256")
        assert fake.calls[0][2] == expected
        assert fake.calls[0][2] != "sw01"

    def test_hmac_via_option_et_via_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Issue #28 : --fingerprint-key OU repli FINGERPRINT_KEY — le _id est
        un HMAC (différent du hash simple, différent par clé)."""
        from omprog import build_bridge, build_parser

        def make(argv: list[str]) -> tuple[Any, FakeOpenSearchClient]:
            args = build_parser().parse_args(
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
                    *argv,
                ]
            )
            bridge = build_bridge(args)
            fake = FakeOpenSearchClient()
            bridge.indexer._client = fake
            return bridge, fake

        doc = {"hostname": "sw01", "message": "x"}
        # 1. Clé via l'option CLI.
        bridge, fake = make(["--fingerprint-key", "cle-option"])
        asyncio.run(bridge.handle_line(json.dumps(doc)))
        asyncio.run(bridge.close())
        with_option = fake.calls[0][2]
        # 2. Clé via la variable d'environnement (repli).
        monkeypatch.setenv("FINGERPRINT_KEY", "cle-env")
        bridge, fake = make([])
        asyncio.run(bridge.handle_line(json.dumps(doc)))
        asyncio.run(bridge.close())
        with_env = fake.calls[0][2]
        # 3. Sans clé : hash simple.
        monkeypatch.delenv("FINGERPRINT_KEY")
        bridge, fake = make([])
        asyncio.run(bridge.handle_line(json.dumps(doc)))
        asyncio.run(bridge.close())
        sans_cle = fake.calls[0][2]

        from pystashtemplate.fingerprint import compute_fingerprint

        assert with_option == compute_fingerprint(doc, ["hostname"], "sha256", key="cle-option")
        assert with_env == compute_fingerprint(doc, ["hostname"], "sha256", key="cle-env")
        assert sans_cle == compute_fingerprint(doc, ["hostname"], "sha256")
        assert len({with_option, with_env, sans_cle}) == 3

    def test_murmur3_via_cli(self, tmp_path: Path) -> None:
        """Issue #28 : --fingerprint-method murmur3 → _id entier décimal."""
        from omprog import build_bridge, build_parser

        args = build_parser().parse_args(
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
            ]
        )
        bridge = build_bridge(args)
        fake = FakeOpenSearchClient()
        bridge.indexer._client = fake
        asyncio.run(bridge.handle_line(json.dumps({"hostname": "sw01", "message": "x"})))
        asyncio.run(bridge.close())
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
        reply = asyncio.run(bridge.handle_line(json.dumps({"message": "app1 connexion"})))
        asyncio.run(bridge.close())
        assert reply == ACK_OK
        assert len(fake.calls) == 1
        index, body, _ = fake.calls[0]
        # L'index vient du output{} rendu, pas du motif quotidien.
        assert index == "logs-test-app1"
        assert body["src"] == "app1"


class TestDebitMinimal:
    def test_200_messages_sous_la_seconde(self, tmp_path: Path) -> None:
        """Garde-fou grossier : 200 messages traités en moins d'une seconde
        (aucun verrou de performance : détecte une régression massive du flux)."""
        bridge, fake = make_bridge(tmp_path, fingerprint="seq")
        lines = [json.dumps({"seq": i, "message": f"event {i}"}) for i in range(200)]
        start = time.monotonic()
        for line in lines:
            reply = asyncio.run(bridge.handle_line(line))
            assert reply == ACK_OK
        elapsed = time.monotonic() - start
        asyncio.run(bridge.close())
        assert len(fake.calls) == 200
        assert len({call[2] for call in fake.calls}) == 200  # _id uniques par champ
        assert elapsed < 1.0, f"débit trop faible : {elapsed:.2f}s pour 200 messages"


# ----------------------------------------------------------------------
# Issue #37 : multi-cluster OpenSearch (failover) et health check périodique
# ----------------------------------------------------------------------


class TestFailoverMultiNoeuds:
    """Failover RÉEL (issue #37) : transport opensearch-py authentique,
    deux serveurs HTTP locaux minimaux — un nœud mort, un nœud vivant.

    La sélection de nœud du transport est rendue déterministe (le nœud
    mort en premier) pour exercer le repli, pas seulement la chance.
    """

    @staticmethod
    async def _start_minimal_opensearch() -> tuple[asyncio.Server, int]:
        """Serveur HTTP minimal qui répond 200 JSON à toute requête."""

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(65536)  # requête complète (corps petits)
            body = b'{"result":"created","_id":"x"}'
            writer.write(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: "
                + str(len(body)).encode()
                + b"\r\nconnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    def test_noeud_mort_bascule_sur_le_suivant(self) -> None:
        async def scenario() -> SendOutcome:
            server, alive_port = await self._start_minimal_opensearch()
            # Port adjacent probablement libre = nœud « mort ».
            dead_port = alive_port + 1
            try:
                indexer = OpenSearchIndexer(
                    hosts=[
                        {"host": "127.0.0.1", "port": dead_port},
                        {"host": "127.0.0.1", "port": alive_port},
                    ],
                    auth=None,
                    index_pattern="switch-logs-%Y.%m.%d",
                    use_ssl=False,
                    verify_certs=False,
                )
                # Le transport choisit normalement un nœud au hasard : on
                # force le nœud mort en premier pour exercer le repli.
                indexer._client.transport.randomizer = lambda: 0
                try:
                    return await indexer.send({"a": 1})
                finally:
                    await indexer.close()
            finally:
                server.close()
                await server.wait_closed()

        assert asyncio.run(scenario()) is SendOutcome.INDEXED

    def test_retry_on_timeout_active(self) -> None:
        """Le repli couvre aussi les délais d'attente (défaut biblio. : False)."""

        async def scenario() -> bool:
            indexer = OpenSearchIndexer(
                hosts=[{"host": "127.0.0.1", "port": 9200}],
                auth=None,
                index_pattern="switch-logs-%Y.%m.%d",
                use_ssl=False,
                verify_certs=False,
            )
            try:
                return indexer._client.transport.retry_on_timeout is True
            finally:
                await indexer.close()

        assert asyncio.run(scenario())


class TestHealthCheckPeriodique:
    def test_health_renvoie_la_version(self, tmp_path: Path) -> None:
        bridge, fake = make_bridge(tmp_path)
        info = asyncio.run(bridge.indexer.health())
        asyncio.run(bridge.close())
        assert info["version"]["number"] == "2.19.0-test"
        assert fake.health_checks == 1

    def test_health_echec_leve(self, tmp_path: Path) -> None:
        import pytest

        bridge, fake = make_bridge(tmp_path)
        fake.mode = "transient"
        with pytest.raises(OpenSearchException):
            asyncio.run(bridge.indexer.health())
        asyncio.run(bridge.close())

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

        asyncio.run(scenario())
        asyncio.run(bridge.close())
        assert fake.health_checks >= 1

    def test_option_cli_defaut_300_et_desactivable(self) -> None:
        parser = build_parser()
        args = parser.parse_args([])
        assert args.health_check_interval == 300
        args_off = parser.parse_args(["--health-check-interval", "0"])
        assert args_off.health_check_interval == 0
