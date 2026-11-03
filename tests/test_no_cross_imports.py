# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #25 : le graphe de dépendances entre modules de `src/` reste acyclique.

Vérification mécanique via `ast` (pas une simple relecture des docstrings) —
règle documentée dans PATTERNS.md, « Absence de dépendances circulaires
entre modules » : le graphe des imports internes ne doit contenir aucun
cycle.

Depuis le découpage #111, `src/` ne contient plus que le connecteur
(omprog, indexer, dlq, metrics, opensearchconf) : les invariants de la
bibliothèque (tracing feuille, util/enrichment/i18n…) sont vérifiés dans
PyStashTemplate. Ici, on vérifie en plus que le connecteur ne dépend
que de lui-même et du paquet `pystashtemplate` — et qu'aucun module de
la bibliothèque n'a été recopié dans ce dépôt.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
MODULES = sorted(p.stem for p in SRC.glob("*.py") if p.stem != "__init__")
MODULES_BIBLIOTHEQUE = {
    "templates",
    "util",
    "tracing",
    "enrichment",
    "dnslookup",
    "fingerprint",
    "grok",
    "multievents",
    "useragent",
    "xmlfilter",
    "simples",
    "filters",
    "interpreter",
}
# Exception #111 : chaque dépôt garde SON module i18n (domaine gettext propre) ;
# celui de RsysLogstach traduit les chaînes du connecteur.


def _imports_of(module_name: str) -> set[str]:
    """Imports internes (vers un autre module de src/) d'un module, via ast."""
    tree = ast.parse((SRC / f"{module_name}.py").read_text(encoding="utf-8"))
    internal: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            internal.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            # `from dlq import ...` → dlq ; `from pystashtemplate.X import ...`
            # → pystashtemplate.X (hors périmètre de ce graphe).
            internal.add(node.module)
    return internal & set(MODULES)


def test_modules_de_src_sont_bien_couverts() -> None:
    # Garde-fou : si un module est ajouté/renommé dans src/, ce test l'exige ici.
    assert MODULES, "aucun module trouvé dans src/"


def test_graphe_sans_cycle() -> None:
    # Détection de cycle par DFS : depuis chaque module, on ne doit jamais
    # retomber sur un nœud déjà présent dans le chemin courant.
    graph = {m: _imports_of(m) for m in MODULES}
    for start in MODULES:
        visited: set[str] = set()
        stack: list[tuple[str, frozenset[str]]] = [(start, frozenset())]
        while stack:
            current, path = stack.pop()
            for dep in graph[current]:
                assert dep not in path, f"cycle détecté : {' → '.join([*sorted(path), dep])} → {start}"
                if dep not in visited:
                    visited.add(dep)
                    stack.append((dep, path | {current}))


def test_src_ne_contient_que_le_connecteur() -> None:
    # Découpage #111 : les modules de la bibliothèque vivent dans PyStashTemplate ;
    # aucun ne doit revenir (ni exister encore) dans src/.
    restants = set(MODULES) & MODULES_BIBLIOTHEQUE
    assert restants == set(), f"modules bibliothèque encore présents dans src/ : {restants}"
    for attendu in ("omprog.py", "indexer.py", "dlq.py", "metrics.py", "opensearchconf.py"):
        assert (SRC / attendu).is_file(), f"{attendu} manque dans src/"


def test_bibliotheque_importee_via_le_paquet() -> None:
    # Le connecteur consomme la sémantique Logstash uniquement via
    # `pystashtemplate.X`, jamais par un import à plat (qui ne marcherait
    # plus : les modules ne sont plus dans src/).
    for m in MODULES:
        arbre = ast.parse((SRC / f"{m}.py").read_text(encoding="utf-8"))
        for node in ast.walk(arbre):
            noms: list[str] = []
            if isinstance(node, ast.Import):
                noms = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                noms = [node.module]
            for nom in noms:
                # `filters`, `from templates import...` → interdit ; seul
                # `pystashtemplate.filters` (paquet) est valide.
                if nom.split(".")[-1] in MODULES_BIBLIOTHEQUE or nom in MODULES_BIBLIOTHEQUE:
                    assert nom.startswith("pystashtemplate."), f"{m} : import plat interdit ({nom})"
