# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #124 : `field_reference.escape_style` (crochets échappés dans les noms de champs)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from test_omprog_complements import _bridge, _run

import templates
from interpreter import PipelineInterpreter
from omprog import build_parser
from templates import ESCAPE_STYLES, parse_field_path, render_template, set_escape_style


@pytest.fixture(autouse=True)
def _style_par_defaut() -> Iterator[None]:
    yield
    set_escape_style("none")


@pytest.mark.parametrize(
    ("style", "expr", "chemin"),
    [
        ("none", "[a%5Bb%5D]", ["a%5Bb%5D"]),
        ("percent", "[a%5Bb%5D][c]", ["a[b]", "c"]),
        ("percent", "x%5D", ["x]"]),
        ("percent", "&#91;", ["&#91;"]),
        ("ampersand", "[&#91;0&#93;]", ["[0]"]),
        ("ampersand", "a%5B", ["a%5B"]),
    ],
)
def test_parse_field_path(style: str, expr: str, chemin: list[str]) -> None:
    set_escape_style(style)
    assert parse_field_path(expr) == chemin


def test_style_inconnu_refuse() -> None:
    with pytest.raises(ValueError, match="escape_style"):
        set_escape_style("html")
    assert templates._REGLAGES["escape_style"] == "none"


def test_gabarit_et_pipeline() -> None:
    set_escape_style("percent")
    doc = {"map[k]": "v"}
    assert render_template("%{map%5Bk%5D}", doc) == "v"
    PipelineInterpreter('filter { mutate { add_field => { "[out%5B1%5D]" => "%{map%5Bk%5D}" } } }').apply(doc)
    assert doc["out[1]"] == "v"


def test_option_ligne_de_commande(tmp_path: Path) -> None:
    assert build_parser().parse_args([]).field_reference_escape_style == "none"
    assert ESCAPE_STYLES == ("none", "percent", "ampersand")
    conf = tmp_path / "p.conf"
    conf.write_text('filter { mutate { copy => { "[a&#91;0&#93;]" => "b" } } }')
    bridge = _bridge("--pipeline-conf", str(conf), "--field-reference-escape-style", "ampersand")
    assert templates._REGLAGES["escape_style"] == "ampersand"
    _run(bridge.close())


class TestCouvertureFuseauxTextuels:
    """Branches de `filters._find_zone_name` / `_apply_zone_name` (#118) restées sans test sur dev."""

    def test_id_inconnu_puis_abreviation(self) -> None:
        from filters import _find_zone_name

        assert _find_zone_name("Mars/Olympus XYZ CET") == "CET"
        assert _find_zone_name("Mars/Olympus") is None

    def test_id_devenu_inconnu(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from datetime import datetime, timezone

        import filters

        def _refus(nom: str) -> None:
            raise filters.ZoneInfoNotFoundError(nom)

        monkeypatch.setattr(filters, "ZoneInfo", _refus)
        assert filters._apply_zone_name(datetime(2026, 1, 1), "Europe/Paris").tzinfo == timezone.utc
