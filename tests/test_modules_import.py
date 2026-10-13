"""Issue #40 : les modules du projet d'origine (joints par Mathilde le 12/10/2026)
s'importent avec les dépendances du projet, sans réseau ni OpenSearch."""

from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize("module", ["enrichment", "filters", "indexer", "interpreter", "templates"])
def test_import(module):
    assert importlib.import_module(module)


def test_api_utilisee_par_les_modules():
    templates = importlib.import_module("templates")
    for nom in (
        "_MISSING",
        "assign_field",
        "parse_field_path",
        "remove_field_path",
        "render_template",
        "resolve_field",
        "CompiledTemplate",
        "compile_template",
        "render",
    ):
        assert hasattr(templates, nom), nom
    assert hasattr(importlib.import_module("interpreter"), "PipelineInterpreter")
