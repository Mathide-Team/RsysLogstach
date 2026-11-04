# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #40 : les modules du connecteur s'importent avec les dépendances du
projet, sans réseau ni OpenSearch — et, depuis le découpage #111, avec la
bibliothèque PyStashTemplate (dépendance figée). Découpage corrigé (#171) :
seuls `omprog` et `i18n` restent dans `src/` ; indexer, dlq, metrics et
opensearchconf viennent du paquet."""

from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize("module", ["i18n", "omprog"])
def test_import(module):
    assert importlib.import_module(module)


@pytest.mark.parametrize(
    "module",
    [
        "pystashtemplate.dlq",
        "pystashtemplate.dnslookup",
        "pystashtemplate.enrichment",
        "pystashtemplate.filters",
        "pystashtemplate.indexer",
        "pystashtemplate.interpreter",
        "pystashtemplate.metrics",
        "pystashtemplate.opensearchconf",
        "pystashtemplate.templates",
    ],
)
def test_import_bibliotheque(module):
    # Découpage #111 : la sémantique Logstash vient du paquet PyStashTemplate.
    assert importlib.import_module(module)


def test_api_utilisee_par_les_modules():
    templates = importlib.import_module("pystashtemplate.templates")
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
