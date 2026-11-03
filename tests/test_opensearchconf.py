# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de `opensearchconf.py` (issue #125) : connexion OpenSearch lue dans le `.conf`."""

from __future__ import annotations

from pathlib import Path

import pytest

import omprog
from interpreter import PipelineInterpreter
from opensearchconf import apply_connection_options, collect_connection_options, conf_auth, conf_host_urls


class FakeIndexer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def _bridge(tmp_path: Path, conf: str, *argv: str) -> FakeIndexer:
    path = tmp_path / "p.conf"
    path.write_text(conf, encoding="utf-8")
    args = omprog.build_parser().parse_args(["--pipeline-conf", str(path), *argv])
    return omprog.build_bridge(args, indexer_factory=lambda **kw: FakeIndexer(**kw)).indexer


@pytest.fixture(autouse=True)
def _no_env_auth(monkeypatch):
    monkeypatch.delenv("OPENSEARCH_USER", raising=False)
    monkeypatch.delenv("OPENSEARCH_PASSWORD", raising=False)


def test_output_plugins_descend_dans_les_branches():
    interp = PipelineInterpreter(
        'output { if [a] { opensearch { hosts => ["h1"] } } else if [b] { stdout {} } '
        'else { elasticsearch { user => "u" } } opensearch { index => "x" } }'
    )
    assert [name for name, _ in interp.output_plugins] == ["opensearch", "stdout", "elasticsearch", "opensearch"]
    assert interp.output_plugins[0][1] == {"hosts": ["h1"]}


def test_conf_complet_lu(tmp_path):
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "c.pem"
    key = tmp_path / "c.key"
    for f in (ca, cert, key):
        f.write_text("x")
    conf = (
        'output { opensearch { hosts => ["os1:9201", "os2"] ssl => true user => "u" password => "p" '
        f'ssl_certificate_verification => false cacert => "{ca}" tls_certificate => "{cert}" tls_key => "{key}" }} }}'
    )
    kw = _bridge(tmp_path, conf).kwargs
    assert kw["hosts"] == [{"host": "os1", "port": 9201}, {"host": "os2", "port": 9200}]
    assert kw["use_ssl"] is True
    assert kw["verify_certs"] is False
    assert kw["auth"] == ("u", "p")
    assert (kw["ca_certs"], kw["client_cert"], kw["client_key"]) == (str(ca), str(cert), str(key))


def test_sans_ssl_le_schema_par_defaut_est_http(tmp_path):
    kw = _bridge(tmp_path, 'output { elasticsearch { hosts => "os1" } }').kwargs
    assert kw["use_ssl"] is False
    assert kw["verify_certs"] is True
    assert kw["auth"] is None


def test_ligne_de_commande_et_environnement_prioritaires(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENSEARCH_USER", "env")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "envpw")
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    conf = 'output { opensearch { hosts => ["http://conf:9200"] user => "u" password => "p" cacert => "/nope" } }'
    kw = _bridge(tmp_path, conf, "--opensearch-host", "https://cli:9300", "--cacert", str(ca)).kwargs
    assert kw["hosts"] == [{"host": "cli", "port": 9300}]
    assert kw["auth"] == ("env", "envpw")
    assert kw["ca_certs"] == str(ca)


def test_sans_bloc_opensearch_defaut_inchange(tmp_path):
    kw = _bridge(tmp_path, "output { stdout {} }").kwargs
    assert kw["hosts"] == [{"host": "localhost", "port": 9200}]
    assert kw["use_ssl"] is True


def test_no_verify_certs_cli_reste_actif(tmp_path):
    kw = _bridge(tmp_path, "output { opensearch { ssl_certificate_verification => true } }", "--no-verify-certs")
    assert kw.kwargs["verify_certs"] is False


def test_booleen_en_chaine():
    assert collect_connection_options([("opensearch", {"ssl": "TRUE", "ssl_certificate_verification": "false"})]) == {
        "ssl": True,
        "ssl_certificate_verification": False,
    }


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"ssl": "oui"}, "true ou false"),
        ({"hosts": []}, "liste d'URLs"),
        ({"hosts": [1]}, "liste d'URLs"),
        ({"cacert": ""}, "chaîne non vide"),
        ({"user": "u"}, "vont ensemble"),
        ({"password": "p"}, "vont ensemble"),
        ({"hosts": ["${OS_HOST}"]}, "non remplacée"),
        ({"password": "${PW}", "user": "u"}, "non remplacée"),
    ],
)
def test_options_invalides(options, message):
    with pytest.raises(ValueError, match=message):
        collect_connection_options([("opensearch", options)])


def test_blocs_contradictoires_refuses():
    with pytest.raises(ValueError, match="différente"):
        collect_connection_options([("opensearch", {"hosts": "a"}), ("elasticsearch", {"hosts": ["b"]})])


def test_blocs_identiques_et_autres_plugins_acceptes():
    plugins = [
        ("opensearch", {"hosts": "a", "index": "x"}),
        ("stdout", {"hosts": "z"}),
        ("opensearch", {"hosts": ["a"]}),
    ]
    assert collect_connection_options(plugins) == {"hosts": ["a"]}


def test_ssl_contredit_le_schema():
    with pytest.raises(ValueError, match="https"):
        conf_host_urls({"hosts": ["https://a"], "ssl": False})
    with pytest.raises(ValueError, match="http://"):
        conf_host_urls({"hosts": ["http://a"], "ssl": True})


def test_urls_normalisees():
    assert conf_host_urls({}) is None
    assert conf_host_urls({"hosts": ["//a:1", "b", "HTTP://c"]}) == ["http://a:1", "http://b", "HTTP://c"]
    assert conf_host_urls({"hosts": ["//a"], "ssl": True}) == ["https://a"]


def test_conf_auth_et_apply_sans_options():
    assert conf_auth({}) is None
    args = omprog.build_parser().parse_args([])
    effective = apply_connection_options(args, {})
    assert effective is not args
    assert effective.opensearch_host is None
    assert effective.no_verify_certs is False
