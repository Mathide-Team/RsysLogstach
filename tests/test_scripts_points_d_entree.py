# SPDX-License-Identifier: GPL-3.0-or-later
"""Points d'entrée et cas limites des scripts de `scripts/` (issue #154, suite de #73).

Chaque script se lance en `python scripts/<nom>.py` : le bloc
`if __name__ == "__main__"` est exécuté ici par `runpy`, dans le processus de
test, pour être mesuré par la couverture.
"""

from __future__ import annotations

import ast
import importlib.util
import runpy
import sys
from pathlib import Path

import pytest
from loguru import logger

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _charger(nom: str):
    spec = importlib.util.spec_from_file_location(f"_{nom}_limites", SCRIPTS / f"{nom}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # requis par @dataclass à l'exécution du module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _puits_loguru():
    """Les `main()` remplacent les puits loguru : on remet le puits par défaut."""
    yield
    logger.remove()
    logger.add(sys.stderr)


@pytest.mark.parametrize(
    ("script", "argv", "codes"),
    [
        ("check_branch_protection", ["--branche", "dev"], {2}),  # dépôt inconnu
        ("i18n_report", [], {0, 1}),
        ("audit_debug_sorties", ["--total"], {0, 1}),
    ],
)
def test_lancement_en_script(monkeypatch, capsys, script, argv, codes):
    monkeypatch.chdir(ROOT)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setattr(sys, "argv", [f"{script}.py", *argv])
    with pytest.raises(SystemExit) as fin:
        runpy.run_path(str(SCRIPTS / f"{script}.py"), run_name="__main__")
    assert fin.value.code in codes
    capsys.readouterr()


def test_traced_en_attribut_reconnu():
    """`@tracing.traced` compte comme `@traced` pour l'audit des sorties."""
    audit = _charger("audit_debug_sorties")
    func = ast.parse("@tracing.traced\ndef f():\n    return 1\n").body[0]
    assert audit._est_tracede(func) is True


def test_suite_de_msgid_plural_ignoree():
    """Une ligne de suite après `msgid_plural` ne modifie ni le msgid ni les msgstr."""
    report = _charger("i18n_report")
    po = 'msgid "fichier"\nmsgid_plural "fichiers"\n" en plus"\nmsgstr[0] "file"\nmsgstr[1] "files"\n'
    assert report.parse_po(po) == [("fichier", ["file", "files"], False)]
