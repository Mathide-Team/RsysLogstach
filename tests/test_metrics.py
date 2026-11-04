# SPDX-License-Identifier: GPL-3.0-or-later
"""Câblage des métriques Prometheus (issue #35) dans `omprog`.

Le module `Metrics` vit dans PyStashTemplate (`pystashtemplate.metrics`,
découpage #111 corrigé, #171) où il est testé ; ici, on vérifie que le
pont l'alimente et garde le préfixe historique `rsyslogstach`.

Sans pytest-asyncio (CLAUDE.md) : `asyncio.run()` direct. L'endpoint HTTP est
démarré pour de vrai sur un port libre de la boucle locale (port 0).
"""

from __future__ import annotations

from prometheus_client.parser import text_string_to_metric_families
from pystashtemplate.indexer import SendOutcome
from pystashtemplate.metrics import Metrics
from test_omprog import FakeIndexer, _args, _bridge, _run
from test_omprog_complements import pont_de_test  # noqa: F401 - fixture réutilisée

import omprog


def _valeurs(metrics: Metrics) -> dict[tuple[str, tuple], float]:
    """Échantillons exposés, indexés par (nom, étiquettes triées)."""
    valeurs = {}
    for famille in text_string_to_metric_families(metrics.render().decode("utf-8")):
        for echantillon in famille.samples:
            valeurs[(echantillon.name, tuple(sorted(echantillon.labels.items())))] = echantillon.value
    return valeurs


def _issue(metrics: Metrics, outcome: str) -> float:
    return _valeurs(metrics)[("rsyslogstach_messages_total", (("outcome", outcome),))]


def _erreur(metrics: Metrics, cause: str) -> float:
    return _valeurs(metrics)[("rsyslogstach_errors_total", (("cause", cause),))]


# --- câblage dans omprog ----------------------------------------------------


def test_options_par_defaut_desactivees():
    args = _args()
    assert args.metrics_port == 0 and args.metrics_addr == "127.0.0.1"


def test_build_bridge_relie_la_dlq(tmp_path):
    dlq = tmp_path / "dlq.jsonl"
    bridge = _bridge("--dlq-path", str(dlq))
    dlq.write_text("abc", encoding="utf-8")
    assert _valeurs(bridge.metrics)[("rsyslogstach_dlq_size_bytes", ())] == 3


def test_issues_comptees_par_le_pont():
    for outcome in (SendOutcome.INDEXED, SendOutcome.RETRYABLE, SendOutcome.DEAD_LETTERED):
        bridge = _bridge(outcome=outcome)
        _run(bridge.handle_line('{"message": "bonjour"}'))
        assert _issue(bridge.metrics, outcome.value) == 1
        valeurs = _valeurs(bridge.metrics)
        assert valeurs[("rsyslogstach_messages_received_total", ())] == 1
        assert valeurs[("rsyslogstach_index_latency_seconds_count", ())] == 1


def test_message_abandonne_par_un_filtre(tmp_path):
    filtres = tmp_path / "filtres.json"
    filtres.write_text('[{"type": "drop", "source": "message", "words": ["bruit"]}]', encoding="utf-8")
    bridge = _bridge("--filters", str(filtres))
    assert _run(bridge.handle_line('{"message": "du bruit"}')) == omprog.ACK_OK
    assert _issue(bridge.metrics, "dropped") == 1
    assert _valeurs(bridge.metrics)[("rsyslogstach_index_latency_seconds_count", ())] == 0


def test_ligne_vide_non_comptee():
    bridge = _bridge()
    _run(bridge.handle_line("  \n"))
    assert _valeurs(bridge.metrics)[("rsyslogstach_messages_received_total", ())] == 0


def test_erreurs_json():
    bridge = _bridge()
    _run(bridge.handle_line("pas du json"))
    _run(bridge.handle_line("[1, 2]"))
    assert _erreur(bridge.metrics, "invalid_json") == 1
    assert _erreur(bridge.metrics, "not_an_object") == 1
    assert _valeurs(bridge.metrics)[("rsyslogstach_messages_received_total", ())] == 2


def test_latence_mesuree_meme_si_l_envoi_echoue():
    class Boom(FakeIndexer):
        async def send(self, doc, **kw):
            raise RuntimeError("boum")

    bridge = omprog.Bridge(indexer=Boom())
    lignes = [b'{"a": 1}\n', b""]

    async def readline():
        return lignes.pop(0)

    _run(omprog.serve(bridge, readline, lambda _r: None))
    assert _erreur(bridge.metrics, "exception") == 1
    assert _valeurs(bridge.metrics)[("rsyslogstach_index_latency_seconds_count", ())] == 1


def test_amain_demarre_et_arrete_l_endpoint(pont_de_test, monkeypatch):  # noqa: F811
    construits, _gabarits, capsys = pont_de_test
    appels = []

    class Serveur:
        arrete = False

        def shutdown(self):
            Serveur.arrete = True

    def faux_serve(self, port, addr):
        appels.append((port, addr))
        return Serveur(), None

    monkeypatch.setattr(omprog.Metrics, "serve", faux_serve)
    args = _args("--metrics-port", "9464", "--metrics-addr", "0.0.0.0", "--health-check-interval", "0")
    assert _run(omprog.amain(args)) == 0
    assert appels == [(9464, "0.0.0.0")]
    assert Serveur.arrete
    assert capsys.readouterr().out == "OK\nOK\n"
    assert _valeurs(construits[0].metrics)[("rsyslogstach_messages_received_total", ())] == 1
