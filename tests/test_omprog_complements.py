# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests complémentaires d'`src/omprog.py` (issue #73).

Options et sorties restées hors tests : `--geoip-db` sur une vraie base
(enrichissement puis fermeture), drop par le pipeline `.conf`, plusieurs
sorties opensearch dont une en échec transitoire, ancien format d'index
template, surveillance de santé, lecture de stdin par un vrai tube, écriture
sur stdout, puis `amain`/`main`/lancement direct avec un indexeur de test
(l'indexeur réel est couvert par `test_script_de_bout_en_bout_sans_opensearch`).
"""

from __future__ import annotations

import asyncio
import os
import runpy
import sys
from pathlib import Path

import pytest
from conftest import IP_STRASBOURG
from loguru import logger
from pystashtemplate.indexer import SendOutcome
from test_omprog import FakeIndexer, _args, _bridge, _run

import omprog

ROOT = Path(__file__).resolve().parents[1]


def test_hote_sans_nom_refuse() -> None:
    with pytest.raises(ValueError, match="--opensearch-host invalide"):
        omprog.parse_hosts(["https://:9200"])


def test_geoip_db_enrichit_puis_ferme(base_geoip_city: str) -> None:
    bridge = _bridge("--geoip-db", base_geoip_city, "--geoip-ip-field", "client", "--geoip-out-field", "geo")
    assert _run(bridge.handle_line(f'{{"client": "{IP_STRASBOURG}"}}')) == "OK"
    envoye = bridge.indexer.sent[0][0]
    assert envoye["geo"]["city_name"] == "Strasbourg"
    fermetures: list[str] = []
    enricher = bridge.enrichers[0]
    fermer = enricher.close
    enricher.close = lambda: (fermetures.append("geoip"), fermer())
    _run(bridge.close())
    assert fermetures == ["geoip"] and bridge.indexer.closed


def test_enrichisseur_sans_close_accepte() -> None:
    class SansClose:
        def enrich(self, doc: dict) -> None:
            doc["vu"] = True

    bridge = omprog.Bridge(indexer=FakeIndexer(), enrichers=[SansClose()])
    _run(bridge.handle_doc({}))
    _run(bridge.close())
    assert bridge.indexer.sent[0][0] == {"vu": True}


def test_drop_du_pipeline_confirme_sans_indexer(tmp_path: Path) -> None:
    # `drop {}` natif n'est pas interprété (limite documentée d'interpreter.py) :
    # l'abandon passe par un step "drop" invoqué via filters_json.
    filtres = tmp_path / "drop.json"
    filtres.write_text('[{"type": "drop", "source": "m", "words": ["bruit"], "mode": "equals"}]')
    conf = tmp_path / "p.conf"
    conf.write_text(f'filter {{ filters_json {{ path => "{filtres}" }} }} output {{ opensearch {{ index => "i" }} }}')
    bridge = _bridge("--pipeline-conf", str(conf))
    assert _run(bridge.handle_doc({"m": "bruit"})) is None
    assert _run(bridge.handle_line('{"m": "bruit"}')) == "OK"
    assert bridge.indexer.sent == []


@pytest.mark.parametrize(
    ("resultats", "attendu"),
    [
        ([SendOutcome.INDEXED, SendOutcome.RETRYABLE], SendOutcome.RETRYABLE),
        ([SendOutcome.RETRYABLE, SendOutcome.INDEXED], SendOutcome.RETRYABLE),
        ([SendOutcome.INDEXED, SendOutcome.INDEXED], SendOutcome.INDEXED),
    ],
)
def test_plusieurs_sorties_un_echec_transitoire_suffit(
    tmp_path: Path, resultats: list[SendOutcome], attendu: SendOutcome
) -> None:
    class Sequence(FakeIndexer):
        async def send(self, doc, *, index=None, document_id=None):
            await super().send(doc, index=index, document_id=document_id)
            return resultats[len(self.sent) - 1]

    conf = tmp_path / "p.conf"
    conf.write_text('output { opensearch { index => "a" } elasticsearch { index => "b" } }')
    bridge = omprog.build_bridge(_args("--pipeline-conf", str(conf)), indexer_factory=lambda **kw: Sequence(**kw))
    assert _run(bridge.handle_doc({})) is attendu
    assert [i for _, i, _ in bridge.indexer.sent] == ["a", "b"]
    bridge.indexer.sent.clear()
    assert _run(bridge.handle_line("{}")) == (omprog.ACK_RETRY if attendu is SendOutcome.RETRYABLE else omprog.ACK_OK)


def test_serve_arret_deja_demande() -> None:
    """Arrêt demandé avant la première lecture : « OK » initial, aucune ligne lue, pont fermé."""
    bridge = omprog.Bridge(indexer=FakeIndexer())
    stop = asyncio.Event()
    stop.set()
    sortie: list[str] = []

    async def readline():  # ne doit jamais être appelée
        raise AssertionError("lecture après l'arrêt")

    assert _run(omprog.serve(bridge, readline, sortie.append, stop)) == 0
    assert sortie == ["OK"] and bridge.indexer.closed


def test_index_template_ancien_format(tmp_path: Path) -> None:
    """Sans `template` : l'ancienne API `_template/{name}` (client httpx, #160)."""
    gabarit = tmp_path / "ancien.json"
    gabarit.write_text('{"index_patterns": ["switch-*"], "mappings": {}}', encoding="utf-8")
    appels: list[str] = []

    class Reponse:
        def raise_for_status(self) -> None:
            return None

    class Client:
        async def put(self, chemin, json=None):
            appels.append(chemin)
            return Reponse()

    _run(omprog.install_index_template(Client(), "switch-logs", str(gabarit)))
    assert appels == ["_template/switch-logs"]


class TestHealthCheckLoop:
    def _lancer(self, sante, tours: int) -> list[str]:
        messages: list[str] = []

        class Indexeur(FakeIndexer):
            async def health(self):
                return sante()

        async def scenario() -> None:
            stop = asyncio.Event()
            bridge = omprog.Bridge(indexer=Indexeur())
            appels = 0
            original = bridge.indexer.health

            async def compter():
                nonlocal appels
                appels += 1
                if appels >= tours:
                    stop.set()
                return await original()

            bridge.indexer.health = compter
            await asyncio.wait_for(omprog.health_check_loop(bridge, 0.01, stop), timeout=5)

        sink = logger.add(lambda m: messages.append(m.record["message"]), level="INFO")
        try:
            _run(scenario())
        finally:
            logger.remove(sink)
        return messages

    def test_etat_journalise_a_chaque_intervalle(self) -> None:
        messages = self._lancer(lambda: {"version": {"number": "2.19.0"}}, tours=2)
        assert messages.count("Health check OpenSearch OK version=2.19.0") == 2

    def test_echec_journalise_sans_arreter(self) -> None:
        def panne():
            raise ConnectionError("cluster injoignable")

        messages = self._lancer(panne, tours=2)
        assert messages.count("Health check OpenSearch échoué erreur=cluster injoignable") == 2

    def test_version_inconnue(self) -> None:
        assert "Health check OpenSearch OK version=?" in self._lancer(dict, tours=1)

    def test_arret_pendant_l_attente(self) -> None:
        async def scenario() -> None:
            stop = asyncio.Event()
            asyncio.get_running_loop().call_later(0.02, stop.set)
            await asyncio.wait_for(omprog.health_check_loop(omprog.Bridge(indexer=FakeIndexer()), 3600, stop), 5)

        _run(scenario())  # se termine dès l'arrêt, sans attendre l'intervalle

    def test_deja_arrete(self) -> None:
        stop = asyncio.Event()
        stop.set()
        _run(omprog.health_check_loop(omprog.Bridge(indexer=FakeIndexer()), 3600, stop))


def test_stdout_une_ligne_par_reponse(capsys: pytest.CaptureFixture[str]) -> None:
    omprog._stdout_writer("Erreur : ligne1\nligne2")
    assert capsys.readouterr().out == "Erreur : ligne1 ligne2\n"


def test_stdin_lu_par_un_vrai_tube(monkeypatch: pytest.MonkeyPatch) -> None:
    lecture, ecriture = os.pipe()
    os.write(ecriture, b'{"a": 1}\n')
    os.close(ecriture)
    with os.fdopen(lecture, "rb") as tube:
        monkeypatch.setattr(sys, "stdin", tube)

        async def scenario() -> list[bytes]:
            readline = await omprog._stdin_reader()
            return [await readline(), await readline()]

        assert _run(scenario()) == [b'{"a": 1}\n', b""]


@pytest.fixture
def pont_de_test(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    """`amain` avec un indexeur de test, stdin = deux lignes puis EOF, stdout capturé."""
    construits: list[omprog.Bridge] = []
    gabarits: list[str] = []

    class Reponse:
        """Réponse HTTP minimale : toujours un succès (raise_for_status muet)."""

        def raise_for_status(self) -> None:
            return None

    class Client:
        """Client httpx minimal : enregistre le nom du gabarit installé."""

        @staticmethod
        async def put(chemin: str, json=None):  # noqa: A002 - imite httpx
            gabarits.append(chemin.rsplit("/", 1)[-1])
            return Reponse()

    def construire(args):
        indexeur = FakeIndexer()
        indexeur._client = lambda: asyncio.sleep(0, result=Client)
        indexeur.health = lambda: asyncio.sleep(0, result={})
        bridge = omprog.Bridge(indexer=indexeur)
        construits.append(bridge)
        return bridge

    async def lecteur():
        lignes = [b'{"a": 1}\n', b""]

        async def readline():
            return lignes.pop(0)

        return readline

    monkeypatch.setattr(omprog, "build_bridge", construire)
    monkeypatch.setattr(omprog, "_stdin_reader", lecteur)
    yield construits, gabarits, capsys
    logger.remove()
    logger.add(sys.stderr)  # main() a remplacé les sorties de loguru


def test_amain_template_sante_et_boucle(pont_de_test) -> None:
    construits, gabarits, capsys = pont_de_test
    args = _args(
        "--index-template", str(ROOT / "opensearch-index-template.json"),
        "--index-template-name", "switch-logs",
        "--health-check-interval", "3600",
    )  # fmt: skip
    assert _run(omprog.amain(args)) == 0
    assert gabarits == ["switch-logs"]
    assert capsys.readouterr().out == "OK\nOK\n"
    assert construits[0].indexer.sent[0][0] == {"a": 1} and construits[0].indexer.closed


def test_main_niveau_de_journal(pont_de_test) -> None:
    construits, gabarits, capsys = pont_de_test
    assert omprog.main(["--log-level", "ERROR", "--health-check-interval", "0"]) == 0  # sans surveillance
    assert gabarits == []
    assert capsys.readouterr().out == "OK\nOK\n"


def test_lancement_direct_aide(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["omprog.py", "--help"])
    with pytest.raises(SystemExit) as fin:
        runpy.run_path(str(ROOT / "src" / "omprog.py"), run_name="__main__")
    assert fin.value.code == 0
    assert "--opensearch-host" in capsys.readouterr().out
