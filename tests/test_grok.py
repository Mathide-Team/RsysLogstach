# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #112 : filtre `grok` natif (`src/grok.py`) et son branchement dans `interpreter`."""

from __future__ import annotations

from pathlib import Path

import pytest

from grok import BASE_PATTERNS, GrokError, GrokFilter, GrokPattern, _convertir, _paires_match, load_patterns_dir
from interpreter import PipelineInterpreter

SYSLOG = "Nov  3 10:00:01 sw1 sshd[123]: Accepted password for root"
APACHE = '1.2.3.4 - - [03/Nov/2026:10:00:00 +0100] "GET /a?b=1 HTTP/1.1" 200 12 "-" "curl/8.5"'


def _conf(doc: dict, corps: str) -> dict:
    interp = PipelineInterpreter(f"filter {{ grok {{ {corps} }} }}")
    interp.apply(doc)
    return doc


class TestMotifsDeBase:
    @pytest.mark.parametrize(
        ("syntaxe", "texte"),
        [
            ("IPV4", "192.168.1.254"),
            ("IPV6", "2001:db8::1"),
            ("IPV6", "fe80::1%eth0"),
            ("IPV6", "::ffff:10.0.0.1"),
            ("IPV6", "1:2:3:4:5:6:7:8"),
            ("IP", "10.0.0.1"),
            ("MAC", "00:1a:2b:3c:4d:5e"),
            ("MAC", "001a.2b3c.4d5e"),
            ("HOSTNAME", "sw1.example.org"),
            ("EMAILADDRESS", "a.b@example.org"),
            ("UUID", "123e4567-e89b-12d3-a456-426614174000"),
            ("TIMESTAMP_ISO8601", "2026-11-03T10:00:00.123+01:00"),
            ("SYSLOGTIMESTAMP", "Nov  3 10:00:01"),
            ("HTTPDATE", "03/Nov/2026:10:00:00 +0100"),
            ("URI", "https://user@example.org:8443/a/b?c=d"),
            ("PATH", "/var/log/syslog"),
            ("PATH", "C:\\Windows\\System32"),
            ("LOGLEVEL", "WARNING"),
            ("QUOTEDSTRING", '"dit \\"bonjour\\""'),
            ("DATESTAMP_RFC2822", "Tue, 3 Nov 2026 10:00:00 +0100"),
            ("TTY", "/dev/pts/3"),
            ("URN", "urn:isbn:0451450523"),
            ("BASE16FLOAT", "0x1A.F"),
        ],
    )
    def test_motif_complet(self, syntaxe: str, texte: str) -> None:
        motif = GrokPattern(f"^%{{{syntaxe}:v}}$", BASE_PATTERNS)
        assert motif.captures(texte, garder_vides=False) == {"v": texte}

    def test_toutes_les_definitions_compilent(self) -> None:
        for nom in BASE_PATTERNS:
            GrokPattern(f"%{{{nom}}}", BASE_PATTERNS)


class TestFiltre:
    def test_syslogbase_et_sous_captures(self) -> None:
        doc = _conf({"message": SYSLOG}, 'match => { "message" => "%{SYSLOGBASE} %{GREEDYDATA:msg}" }')
        assert doc["program"] == "sshd"
        assert doc["pid"] == "123"
        assert doc["logsource"] == "sw1"
        assert doc["msg"] == "Accepted password for root"

    def test_combinedapachelog(self) -> None:
        doc = _conf({"message": APACHE}, 'match => { "message" => "%{COMBINEDAPACHELOG}" }')
        assert (doc["clientip"], doc["verb"], doc["response"], doc["agent"]) == ("1.2.3.4", "GET", "200", '"curl/8.5"')

    def test_types_et_champs_imbriques(self) -> None:
        doc = _conf(
            {"message": "10.0.0.1 42 3.5 abc"},
            'match => { "message" => "%{IP:[src][ip]} %{NUMBER:n:int} %{NUMBER:f:float} %{WORD:w:int}" }',
        )
        assert doc["src"] == {"ip": "10.0.0.1"}
        assert (doc["n"], doc["f"], doc["w"]) == (42, 3.5, "abc")

    def test_ancienne_forme_tableau(self) -> None:
        doc = _conf({"message": "id=7"}, 'match => ["message", "id=%{INT:id:integer}"]')
        assert doc["id"] == 7

    def test_echec_tag_par_defaut_et_personnalise(self) -> None:
        assert _conf({"message": "x"}, 'match => { "message" => "%{IP:ip}" }')["tags"] == ["_grokparsefailure"]
        doc = _conf({"message": "x"}, 'match => { "message" => "%{IP:ip}" } tag_on_failure => ["_g"]')
        assert doc["tags"] == ["_g"]

    def test_champ_absent_ou_null(self) -> None:
        assert _conf({"autre": 1}, 'match => { "message" => "%{IP:ip}" }')["tags"] == ["_grokparsefailure"]
        assert _conf({"message": None}, 'match => { "message" => "%{IP:ip}" }')["tags"] == ["_grokparsefailure"]

    def test_options_communes_apres_succes(self) -> None:
        doc = _conf({"message": "10.0.0.1"}, 'match => { "message" => "%{IP:ip}" } add_tag => ["grok_ok"]')
        assert doc["tags"] == ["grok_ok"]

    def test_break_on_match(self) -> None:
        corps = 'match => { "message" => ["%{WORD:a}", "%{INT:b}"] }'
        assert "b" not in _conf({"message": "x 1"}, corps)
        doc = _conf({"message": "x 1"}, corps + " break_on_match => false")
        assert (doc["a"], doc["b"]) == ("x", "1")

    def test_break_on_match_entre_champs(self) -> None:
        corps = 'match => { "message" => "%{WORD:a}" "autre" => "%{INT:b}" }'
        assert "b" not in _conf({"message": "x", "autre": "1"}, corps)

    def test_valeur_tableau(self) -> None:
        doc = _conf({"message": ["--", "id=3"]}, 'match => { "message" => "id=%{INT:id}" }')
        assert doc["id"] == "3"

    def test_overwrite_et_ajout(self) -> None:
        doc = _conf(
            {"message": "404 introuvable"},
            'match => { "message" => "%{INT:code} %{WORD:message}" } overwrite => ["message"]',
        )
        assert (doc["message"], doc["code"]) == ("introuvable", "404")
        doc = _conf({"message": "a", "w": "avant"}, 'match => { "message" => "%{WORD:w}" }')
        assert doc["w"] == ["avant", "a"]
        doc = _conf({"message": "a", "w": ["x"]}, 'match => { "message" => "%{WORD:w}" }')
        assert doc["w"] == ["x", "a"]
        doc = _conf({"message": "a", "w": None}, 'match => { "message" => "%{WORD:w}" } overwrite => "w"')
        assert doc["w"] == "a"

    def test_target(self) -> None:
        doc = _conf({"message": "10.0.0.1"}, 'match => { "message" => "%{IP:ip}" } target => "[g]"')
        assert doc["g"] == {"ip": "10.0.0.1"}

    def test_captures_vides(self) -> None:
        corps = 'match => { "message" => "a=%{DATA:a};" }'
        assert "a" not in _conf({"message": "a=;"}, corps)
        assert _conf({"message": "a=;"}, corps + " keep_empty_captures => true")["a"] == ""

    def test_capture_oniguruma_et_pattern_definitions(self) -> None:
        doc = _conf(
            {"message": "404 introuvable"},
            'match => { "message" => "(?<code>[0-9]{3}) %{MOT:texte}" } pattern_definitions => { "MOT" => "[a-z]+" }',
        )
        assert (doc["code"], doc["texte"]) == ("404", "introuvable")

    def test_patterns_dir(self, tmp_path: Path) -> None:
        (tmp_path / "perso").write_text("# commentaire\n\nSANSVALEUR\nCODE [A-Z]{3}\n", encoding="utf-8")
        doc = _conf({"message": "id ABC"}, f'match => {{ "message" => "%{{CODE:c}}" }} patterns_dir => ["{tmp_path}"]')
        assert doc["c"] == "ABC"
        doc = _conf({"message": "ABC"}, f'match => {{ "message" => "%{{CODE:c}}" }} patterns_dir => "{tmp_path}"')
        assert doc["c"] == "ABC"

    def test_motif_inconnu_ou_invalide(self) -> None:
        assert _conf({"message": "a"}, 'match => { "message" => "%{INCONNU:x}" }')["tags"] == ["_grokparsefailure"]
        assert _conf({"message": "a"}, 'match => { "message" => "(" }')["tags"] == ["_grokparsefailure"]

    def test_compile_une_fois_par_bloc(self) -> None:
        interp = PipelineInterpreter('filter { grok { match => { "message" => "%{INT:n}" } } }')
        interp.apply({"message": "1"})
        interp.apply({"message": "2"})
        assert len(interp._grok_cache) == 1


class TestFonctions:
    def test_recursion(self) -> None:
        with pytest.raises(GrokError, match="trop imbriqué"):
            GrokPattern("%{A}", {"A": "%{A}"})

    def test_meme_champ_plusieurs_fois(self) -> None:
        motif = GrokPattern("%{INT:n} %{INT:n} %{INT:n}", BASE_PATTERNS)
        assert motif.captures("1 2 3", garder_vides=False) == {"n": ["1", "2", "3"]}

    def test_convertir(self) -> None:
        assert _convertir("4.9", "int") == 4
        assert _convertir("x", "float") == "x"
        assert _convertir("1", "inconnu") == "1"

    @pytest.mark.parametrize("match", [None, ["message"], ["a", "b", "c"], [1, "x"], {"m": 3}])
    def test_match_mal_forme(self, match: object) -> None:
        assert _paires_match(match) == []
        assert GrokFilter({"match": match}).regles == []

    def test_patterns_dir_illisible(self, tmp_path: Path) -> None:
        assert load_patterns_dir([str(tmp_path / "absent")]) == {}
        (tmp_path / "bin").write_bytes(b"\xff\xfe")
        assert load_patterns_dir([str(tmp_path)]) == {}
