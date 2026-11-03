# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de `scripts/check_branch_protection.py` (issue #154, suite de #73).

Comparaison de la règle versionnée avec la protection publique de la branche,
codes de sortie de `main()` (0 conforme, 1 écart ou erreur d'API, 2 dépôt
inconnu ou règle absente/illisible). Aucun appel réseau : `urlopen` est
remplacé par une doublure.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest
from loguru import logger

ROOT = Path(__file__).resolve().parents[1]


def _charger():
    spec = importlib.util.spec_from_file_location(
        "check_branch_protection", ROOT / "scripts" / "check_branch_protection.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_branch_protection"] = module
    spec.loader.exec_module(module)
    return module


cbp = _charger()

REGLE = {
    "required_status_checks": {"strict": True, "checks": [{"context": "Qualité", "app_id": 1}]},
    "enforce_admins": True,
}


def _branche(checks=("Qualité",), niveau="everyone", protegee=True):
    return {
        "protected": protegee,
        "protection": {"required_status_checks": {"enforcement_level": niveau, "contexts": list(checks)}},
    }


@pytest.fixture(autouse=True)
def _puits_loguru():
    """`main()` remplace les puits loguru : on remet le puits par défaut après chaque test."""
    yield
    logger.remove()
    logger.add(sys.stderr)


# --- checks_attendus / comparer ------------------------------------------


def test_checks_attendus_checks_et_contexts():
    regle = {"required_status_checks": {"checks": [{"context": "a"}], "contexts": ["b"]}}
    assert cbp.checks_attendus(regle) == {"a", "b"}


def test_checks_attendus_sans_checks_requis():
    assert cbp.checks_attendus({"required_status_checks": None}) == set()


@pytest.mark.parametrize("branche", ["dev", "main"])
def test_regles_versionnees_lisibles(branche):
    """Les règles du dépôt se lisent et exigent au moins le job Qualité."""
    regle = json.loads((ROOT / ".github" / "branch-protection" / f"{branche}.json").read_text(encoding="utf-8"))
    assert "Qualité (lint, format, tests)" in cbp.checks_attendus(regle)


def test_conforme():
    assert cbp.comparer(REGLE, _branche()) == []


def test_branche_non_protegee():
    assert cbp.comparer(REGLE, {"protected": False}) == ["la branche n'est pas protégée"]


def test_checks_manquants_et_en_trop():
    ecarts = cbp.comparer(REGLE, _branche(checks=("Autre",)))
    assert ecarts == ["checks requis absents : Qualité", "checks requis non prévus par la règle : Autre"]


def test_application_aux_administrateurs():
    assert cbp.comparer(REGLE, _branche(niveau="non_admins")) == [
        "application aux administrateurs : attendu True, réel False"
    ]


def test_administrateurs_ignores_sans_checks_requis():
    """Sans checks attendus, enforcement_level n'est pas significatif : pas d'écart."""
    branche = {"protected": True, "protection": {}}
    assert cbp.comparer({"enforce_admins": True}, branche) == []


# --- lire_protection -------------------------------------------------------


class _Reponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize("jeton", ["secret", None])
def test_lire_protection(monkeypatch, jeton):
    vues = []

    def urlopen(requete, timeout):
        vues.append((requete, timeout))
        return _Reponse(b'{"protected": true}')

    monkeypatch.setattr(cbp.urllib.request, "urlopen", urlopen)
    assert cbp.lire_protection("org/depot", "dev", jeton) == {"protected": True}
    requete, timeout = vues[0]
    assert requete.full_url == "https://api.github.com/repos/org/depot/branches/dev"
    assert timeout == 30
    assert requete.get_header("Authorization") == (f"Bearer {jeton}" if jeton else None)


# --- main ------------------------------------------------------------------


def _main(monkeypatch, tmp_path, *argv, regle=REGLE, lecture=None, debug=False):
    regles = tmp_path / "regles"
    regles.mkdir(exist_ok=True)
    if regle is not None:
        (regles / "dev.json").write_text(regle if isinstance(regle, str) else json.dumps(regle), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["check_branch_protection.py", "--regles", str(regles), *argv])
    monkeypatch.setenv("GITHUB_TOKEN", "jeton")
    if debug:
        monkeypatch.setenv("SOCLE_DEBUG", "1")
    else:
        monkeypatch.delenv("SOCLE_DEBUG", raising=False)
    if lecture is not None:
        monkeypatch.setattr(cbp, "lire_protection", lecture)
    return cbp.main()


def test_main_conforme(monkeypatch, tmp_path, capsys):
    vu = []

    def lecture(depot, branche, jeton):
        vu.append((depot, branche, jeton))
        return _branche()

    assert _main(monkeypatch, tmp_path, "--branche", "dev", "--depot", "org/depot", lecture=lecture, debug=True) == 0
    assert vu == [("org/depot", "dev", "jeton")]
    assert "Protection de dev conforme" in capsys.readouterr().out


def test_main_ecart(monkeypatch, tmp_path, capsys):
    code = _main(monkeypatch, tmp_path, "--branche", "dev", "--depot", "o/d", lecture=lambda *a: {"protected": False})
    sortie = capsys.readouterr().out
    assert code == 1
    assert "::error::dev : la branche n'est pas protégée" in sortie
    assert "gh api -X PUT repos/o/d/branches/dev/protection" in sortie


def test_main_depot_inconnu(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    assert _main(monkeypatch, tmp_path, "--branche", "dev") == 2
    assert "dépôt inconnu" in capsys.readouterr().out


def test_main_depot_depuis_environnement(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_REPOSITORY", "org/env")
    vu = []
    _main(monkeypatch, tmp_path, "--branche", "dev", lecture=lambda d, b, j: vu.append(d) or _branche())
    assert vu == ["org/env"]


def test_main_regle_absente(monkeypatch, tmp_path, capsys):
    assert _main(monkeypatch, tmp_path, "--branche", "dev", "--depot", "o/d", regle=None) == 2
    assert "règle absente" in capsys.readouterr().out


def test_main_regle_illisible(monkeypatch, tmp_path, capsys):
    assert _main(monkeypatch, tmp_path, "--branche", "dev", "--depot", "o/d", regle="{ pas du json") == 2
    assert "règle illisible" in capsys.readouterr().out


def test_main_erreur_http(monkeypatch, tmp_path, capsys):
    def lecture(*_):
        raise urllib.error.HTTPError("https://api.github.com", 404, "Not Found", {}, None)

    assert _main(monkeypatch, tmp_path, "--branche", "dev", "--depot", "o/d", lecture=lecture) == 1
    assert "HTTP 404" in capsys.readouterr().out


def test_main_api_injoignable(monkeypatch, tmp_path, capsys):
    def lecture(*_):
        raise urllib.error.URLError("réseau coupé")

    assert _main(monkeypatch, tmp_path, "--branche", "dev", "--depot", "o/d", lecture=lecture) == 1
    assert "API GitHub injoignable : réseau coupé" in capsys.readouterr().out
