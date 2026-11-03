# SPDX-License-Identifier: GPL-3.0-or-later
"""Packaging installable (issue #31) : contrats du pyproject.toml.

La roue doit exposer les modules au niveau RACINE (même disposition que
`PYTHONPATH=src`) : c'est ce qui permet `pip install rsyslogstach` sans
toucher aux imports existants (`from filters import ...`, conftest, tests).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import omprog

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


class TestPyproject:
    def test_backend_de_build_present(self) -> None:
        # Sans backend PEP 517, pas de `pip install` possible.
        build = _pyproject()["build-system"]
        assert build["requires"] == ["hatchling"]
        assert build["build-backend"] == "hatchling.build"

    def test_roue_modules_a_la_racine(self) -> None:
        # `sources = ["src"]` renomme src/ à la racine de la roue : les
        # modules s'installent comme le faisait PYTHONPATH=src — tous les
        # imports existants restent valides.
        wheel = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]
        assert wheel["only-include"] == ["src"]
        assert wheel["sources"] == ["src"]

    def test_uv_package_true(self) -> None:
        # uv doit installer le projet lui-même (pas seulement ses dépendances).
        assert _pyproject()["tool"]["uv"]["package"] is True

    def test_script_console(self) -> None:
        # `rsyslogstach` remplace `PYTHONPATH=src python3 src/omprog.py`.
        assert _pyproject()["project"]["scripts"]["rsyslogstach"] == "omprog:main"
        # La cible existe et est appelable.
        assert callable(omprog.main)

    def test_modules_exposes_a_la_racine_de_la_roue(self) -> None:
        # Garde-fou sur la DISPOSITION : le connecteur doit rester des
        # fichiers à plat dans src/ (pas de sous-package) — sinon la roue
        # n'exposerait plus les noms attendus au niveau racine. Depuis le
        # découpage #111, la bibliothèque (filters, templates...) vient du
        # paquet pystashtemplate, pas de src/.
        src = Path(__file__).resolve().parents[1] / "src"
        modules = sorted(p.name for p in src.glob("*.py"))
        assert "omprog.py" in modules
        assert "filters.py" not in modules, "filters.py (bibliothèque) doit venir de pystashtemplate, plus de src/"
        assert not (src / "__init__.py").exists(), "src/ doit rester à plat (modules top-level), pas un package « src »"


class TestTraductions:
    """Issue #38 : les catalogues compilés font partie de la roue."""

    def test_catalogues_en_donnees_partagees(self) -> None:
        # Tout lang/locale/ (un dossier par langue de lang/LINGUAS) devient
        # <prefix>/share/locale/ : ajouter une langue ne touche pas au pyproject.
        wheel = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]
        assert wheel["shared-data"] == {"lang/locale": "share/locale"}
