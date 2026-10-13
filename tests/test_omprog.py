"""Tests de `omprog.py` (issue #40) : chaîne de traitement et protocole omprog.

Sans pytest-asyncio (CLAUDE.md) : `asyncio.run()` direct. L'indexeur est un
double de test ; le test de bout en bout lance le vrai script contre un port
fermé (échec transitoire attendu, sans OpenSearch).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import omprog
from indexer import SendOutcome
from interpreter import PipelineInterpreter

ROOT = Path(__file__).resolve().parents[1]


class FakeIndexer:
    def __init__(self, outcome: SendOutcome = SendOutcome.INDEXED, **kwargs):
        self.kwargs = kwargs
        self.outcome = outcome
        self.sent: list[tuple[dict, str | None, str | None]] = []
        self.closed = False

    async def send(self, doc, *, index=None, document_id=None):
        self.sent.append((json.loads(json.dumps(doc)), index, document_id))
        return self.outcome

    async def close(self):
        self.closed = True


def _args(*argv: str):
    return omprog.build_parser().parse_args(list(argv))


def _bridge(*argv: str, outcome: SendOutcome = SendOutcome.INDEXED) -> omprog.Bridge:
    return omprog.build_bridge(_args(*argv), indexer_factory=lambda **kw: FakeIndexer(outcome, **kw))


def _run(coro):
    return asyncio.run(coro)


# --- options -------------------------------------------------------------


def test_options_du_readme_acceptees(tmp_path):
    args = _args(
        "--filters",
        str(ROOT / "filters.example.json"),
        "--enrich-dict",
        str(ROOT / "enrich-dict.example.json"),
        "--pipeline-conf",
        str(ROOT / "pipeline.example.d"),
        "--opensearch-host",
        "https://localhost:9200",
        "--index-template",
        str(ROOT / "opensearch-index-template.json"),
        "--dlq-path",
        str(tmp_path / "dlq.jsonl"),
    )
    assert args.pipeline_conf.endswith("pipeline.example.d")
    assert args.dlq_max_size == 0 and args.dlq_backups == 0


def test_options_dlq_cablees(tmp_path):
    bridge = _bridge(
        "--dlq-path",
        str(tmp_path / "dlq.jsonl"),
        "--dlq-max-size",
        "100M",
        "--dlq-max-age",
        "7d",
        "--dlq-backups",
        "10",
        "--dlq-retention",
        "30d",
        "--dlq-no-compress",
    )
    dlq = bridge.indexer.kwargs["dlq"]
    assert dlq is bridge.dlq
    assert dlq._max_bytes == 100 * 1024 * 1024
    assert dlq._backups == 10
    assert dlq._compress is False


def test_dlq_taille_invalide_refusee():
    with pytest.raises(SystemExit):
        _args("--dlq-max-size", "beaucoup")


@pytest.mark.parametrize(
    ("urls", "hosts", "ssl"),
    [
        (None, [{"host": "localhost", "port": 9200}], True),
        (["http://os1:9201", "http://os2"], [{"host": "os1", "port": 9201}, {"host": "os2", "port": 9200}], False),
        (["os3:9300"], [{"host": "os3", "port": 9300}], True),
    ],
)
def test_parse_hosts(urls, hosts, ssl):
    assert omprog.parse_hosts(urls) == (hosts, ssl)


def test_parse_hosts_schemas_melanges():
    with pytest.raises(ValueError):
        omprog.parse_hosts(["http://a", "https://b"])


def test_indexeur_recoit_les_options(monkeypatch):
    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "secret")
    bridge = _bridge("--document-id-fingerprint", "host,msg", "--fingerprint-method", "sha1", "--no-verify-certs")
    kw = bridge.indexer.kwargs
    assert kw["auth"] == ("admin", "secret")
    assert kw["document_id_fingerprint_fields"] == ["host", "msg"]
    assert kw["document_id_fingerprint_method"] == "sha1"
    assert kw["verify_certs"] is False
    assert kw["index_pattern"] == omprog.DEFAULT_INDEX_PATTERN


def test_empreinte_du_document_entier():
    assert _bridge("--document-id-fingerprint", "*").indexer.kwargs["document_id_fingerprint_fields"] == []


def test_pas_de_secret_en_option():
    aide = omprog.build_parser().format_help()
    assert "--password" not in aide and "--user" not in aide


# --- chaîne de traitement ------------------------------------------------


def test_message_indexe():
    bridge = _bridge()
    assert _run(bridge.handle_line('{"msg": "bonjour", "hostname": "sw-core-01"}\n')) == "OK"
    assert bridge.indexer.sent == [({"msg": "bonjour", "hostname": "sw-core-01"}, None, None)]


def test_echec_transitoire_demande_le_renvoi():
    bridge = _bridge(outcome=SendOutcome.RETRYABLE)
    assert _run(bridge.handle_line('{"msg": "x"}')) == omprog.ACK_RETRY != "OK"


def test_dead_lettered_confirme():
    bridge = _bridge(outcome=SendOutcome.DEAD_LETTERED)
    assert _run(bridge.handle_line('{"msg": "x"}')) == "OK"


def test_ligne_vide_confirmee_sans_indexation():
    bridge = _bridge()
    assert _run(bridge.handle_line("\n")) == "OK"
    assert bridge.indexer.sent == []


def test_json_invalide_en_dlq_puis_confirme(tmp_path):
    dlq_path = tmp_path / "dlq.jsonl"
    bridge = _bridge("--dlq-path", str(dlq_path))
    assert _run(bridge.handle_line("pas du json")) == "OK"
    assert _run(bridge.handle_line("[1, 2]")) == "OK"
    lignes = [json.loads(line) for line in dlq_path.read_text(encoding="utf-8").splitlines()]
    assert len(lignes) == 2
    assert "pas du json" in json.dumps(lignes[0], ensure_ascii=False)
    assert bridge.indexer.sent == []


def test_filtres_drop_et_enrichissement(tmp_path):
    filtres = tmp_path / "filters.json"
    filtres.write_text(json.dumps([{"type": "drop", "source": "msg", "words": ["keepalive"]}]), encoding="utf-8")
    bridge = _bridge("--filters", str(filtres), "--enrich-dict", str(ROOT / "enrich-dict.example.json"))
    assert _run(bridge.handle_line('{"msg": "keepalive ok", "hostname": "sw-core-01"}')) == "OK"
    assert bridge.indexer.sent == []
    assert _run(bridge.handle_line('{"msg": "link down", "hostname": "sw-core-01"}')) == "OK"
    ((doc, _, _),) = bridge.indexer.sent
    assert doc["enrichment"]["site"] == "Besançon - DR"


def test_filtres_exemple_du_depot(tmp_path):
    words = tmp_path / "blocklist.txt"
    words.write_text("keepalive\n", encoding="utf-8")
    steps = json.loads((ROOT / "filters.example.json").read_text(encoding="utf-8"))
    steps[0]["words_file"] = str(words)
    filtres = tmp_path / "filters.json"
    filtres.write_text(json.dumps(steps), encoding="utf-8")
    bridge = _bridge("--filters", str(filtres))
    msg = "%%10IFNET/3/LINK_UPDOWN: user=admin action=down"
    assert _run(bridge.handle_line(json.dumps({"msg": msg}))) == "OK"
    ((doc, _, _),) = bridge.indexer.sent
    assert doc["module"] == "IFNET"
    assert doc["severity_code"] == 3
    assert doc["kv_user"] == "admin"
    assert "msg" not in doc


def test_pipeline_sans_output_garde_la_destination_statique(tmp_path):
    conf = tmp_path / "p.conf"
    conf.write_text('filter { mutate { add_field => { "via" => "pipeline" } } }', encoding="utf-8")
    bridge = _bridge("--pipeline-conf", str(conf))
    assert _run(bridge.handle_line('{"msg": "x"}')) == "OK"
    ((doc, index, _),) = bridge.indexer.sent
    assert doc["via"] == "pipeline" and index is None


def test_pipeline_output_opensearch_donne_index_et_id(tmp_path):
    conf = tmp_path / "p.conf"
    conf.write_text(
        'output { if [type] == "a" { opensearch { index => "logs-%{type}" document_id => "%{eid}" } } }',
        encoding="utf-8",
    )
    bridge = _bridge("--pipeline-conf", str(conf))
    assert _run(bridge.handle_line('{"type": "a", "eid": "42"}')) == "OK"
    assert _run(bridge.handle_line('{"type": "b", "eid": "43"}')) == "OK"
    assert [(i, d) for _, i, d in bridge.indexer.sent] == [("logs-a", "42")]


def test_pipeline_dossier_lu_par_ordre_de_nom(tmp_path):
    (tmp_path / "20_b.conf").write_text('filter { mutate { add_field => { "b" => "2" } } }', encoding="utf-8")
    (tmp_path / "10_a.conf").write_text('filter { mutate { add_field => { "a" => "1" } } }', encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignoré", encoding="utf-8")
    source = omprog.read_pipeline_source(str(tmp_path))
    assert source.index('"a"') < source.index('"b"') and "ignoré" not in source
    PipelineInterpreter(source)


def test_pipeline_dossier_vide(tmp_path):
    with pytest.raises(ValueError):
        omprog.read_pipeline_source(str(tmp_path))


def test_pipeline_exemple_du_depot_se_compile():
    PipelineInterpreter(omprog.read_pipeline_source(str(ROOT / "pipeline.example.d")))


def test_sortie_non_geree_ignoree():
    class Interp:
        has_output = True

        def apply(self, doc, **kw):
            from interpreter import OutputAction

            return [OutputAction("stdout", {}), OutputAction("opensearch", {"index": ["idx"], "document_id": ""})]

        def close(self):
            pass

    bridge = omprog.Bridge(indexer=FakeIndexer(), interpreter=Interp())
    assert _run(bridge.handle_doc({"m": 1})) is SendOutcome.INDEXED
    assert [(i, d) for _, i, d in bridge.indexer.sent] == [("idx", None)]


# --- boucle omprog -------------------------------------------------------


def test_serve_ok_initial_puis_une_reponse_par_ligne():
    bridge = omprog.Bridge(indexer=FakeIndexer())
    lignes = [b'{"a": 1}\n', b"\n", b"pas du json\n", b""]
    sortie: list[str] = []

    async def readline():
        return lignes.pop(0)

    assert _run(omprog.serve(bridge, readline, sortie.append)) == 3
    assert sortie == ["OK", "OK", "OK", "OK"]
    assert bridge.indexer.closed


def test_serve_exception_inattendue_ne_stoppe_pas():
    class Boom(FakeIndexer):
        async def send(self, doc, **kw):
            raise RuntimeError("boum")

    bridge = omprog.Bridge(indexer=Boom())
    lignes = [b'{"a": 1}\n', b'{"a": 2}\n', b""]
    sortie: list[str] = []

    async def readline():
        return lignes.pop(0)

    assert _run(omprog.serve(bridge, readline, sortie.append)) == 2
    assert sortie[0] == "OK" and all(r.startswith("Erreur") for r in sortie[1:])


def test_serve_arret_sur_signal():
    async def scenario():
        bridge = omprog.Bridge(indexer=FakeIndexer())
        stop = asyncio.Event()

        async def readline():
            await asyncio.sleep(3600)
            return b""

        asyncio.get_running_loop().call_later(0.05, stop.set)
        n = await omprog.serve(bridge, readline, lambda _r: None, stop)
        return n, bridge.indexer.closed

    assert _run(scenario()) == (0, True)


def test_index_template_composable():
    class Indices:
        def __init__(self):
            self.calls = []

        async def put_index_template(self, name, body):
            self.calls.append(("composable", name, sorted(body)))

        async def put_template(self, name, body):
            self.calls.append(("ancien", name, sorted(body)))

    class Client:
        indices = Indices()

    _run(omprog.install_index_template(Client, "switch-logs", str(ROOT / "opensearch-index-template.json")))
    assert Client.indices.calls == [("composable", "switch-logs", ["index_patterns", "priority", "template"])]


def test_script_de_bout_en_bout_sans_opensearch(tmp_path):
    """Le vrai script : « OK » au démarrage, échec transitoire sur un nœud injoignable, arrêt à EOF."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    env.pop("OPENSEARCH_USER", None)
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "src" / "omprog.py"),
            "--opensearch-host",
            "http://127.0.0.1:9",
            "--log-level",
            "ERROR",
        ],
        input='{"msg": "x"}\n',
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == ["OK", omprog.ACK_RETRY]
