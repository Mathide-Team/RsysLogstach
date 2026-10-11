"""Tests de templates.py (module reconstruit, issue #40)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from templates import get_field, parse_field_path, render_template

DOC = {
    "hostname": "sw01",
    "host": {"ip": "10.0.0.1", "tags": ["core", "lab"]},
    "count": 3,
    "up": True,
    "nothing": None,
}


class TestParseFieldPath:
    @pytest.mark.parametrize(
        ("ref", "path"),
        [("hostname", ["hostname"]), ("[host][ip]", ["host", "ip"]), ("[a]", ["a"]), (" x ", ["x"])],
    )
    def test_valid(self, ref, path):
        assert parse_field_path(ref) == path

    @pytest.mark.parametrize("ref", ["", "  ", "[a][b", "a[b]", "[a]x[b]", "[]", "a]"])
    def test_invalid(self, ref):
        with pytest.raises(ValueError):
            parse_field_path(ref)


class TestGetField:
    def test_nested_and_list_index(self):
        assert get_field(DOC, "[host][ip]") == "10.0.0.1"
        assert get_field(DOC, "[host][tags][1]") == "lab"
        assert get_field(DOC, "[host][tags][-1]") == "lab"

    def test_missing_returns_default(self):
        assert get_field(DOC, "absent") is None
        assert get_field(DOC, "[host][absent]", "d") == "d"
        assert get_field(DOC, "[host][tags][5]", "d") == "d"
        assert get_field(DOC, "[hostname][x]", "d") == "d"

    def test_null_is_present(self):
        assert get_field(DOC, "nothing", "d") is None


class TestRenderTemplate:
    def test_simple_and_nested(self):
        assert render_template("%{hostname}-%{[host][ip]}", DOC) == "sw01-10.0.0.1"

    def test_value_formatting(self):
        assert render_template("%{count}|%{up}|%{nothing}", DOC) == "3|true|"
        assert render_template("%{[host][tags]}", DOC) == '["core","lab"]'
        assert render_template("%{host}", DOC) == '{"ip":"10.0.0.1","tags":["core","lab"]}'

    def test_without_reference(self):
        assert render_template("texte fixe", DOC) == "texte fixe"
        assert render_template("", DOC) == ""

    def test_missing_keep_is_default(self):
        assert render_template("a-%{absent}-b", DOC) == "a-%{absent}-b"

    def test_missing_empty(self):
        assert render_template("a-%{absent}-b", DOC, on_missing="empty") == "a--b"

    def test_missing_raise(self):
        with pytest.raises(KeyError, match="absent"):
            render_template("%{absent}", DOC, on_missing="raise")

    def test_unknown_on_missing(self):
        with pytest.raises(ValueError, match="on_missing"):
            render_template("%{hostname}", DOC, on_missing="ignore")

    def test_null_renders_like_missing_empty(self):
        """Limite documentée (#29) : null et absent donnent tous deux ''."""
        assert render_template("%{nothing}", DOC, on_missing="empty") == render_template(
            "%{absent}", DOC, on_missing="empty"
        )


def test_templates_has_no_dependency_on_fingerprint():
    """PATTERNS.md : templates est une feuille, il ne dépend que de tracing."""
    tree = ast.parse((Path(__file__).resolve().parents[1] / "src" / "templates.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
    local = {p.stem for p in (Path(__file__).resolve().parents[1] / "src").glob("*.py")}
    assert imported & local == {"tracing"}
