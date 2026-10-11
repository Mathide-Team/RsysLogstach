"""Rendu des gabarits `%{...}` (syntaxe sprintf de Logstash).

Module RECONSTRUIT le 11/10/2026 (issue #40) : le `templates.py` d'origine
n'a jamais été poussé (absent de l'historique de Mathide-Team/RsysLogstach
et de MathildeDec/RsysLogstach). Le contrat est repris de la documentation
du dépôt (README, CLAUDE.md, FEATURES.md, PATTERNS.md) et de son seul
appelant, `fingerprint.py` :

- `%{champ}` : champ de premier niveau ; `%{[a][b]}` : champ imbriqué ;
- un champ présent mais `null` se rend en chaîne vide, comme un champ
  absent rendu avec `on_missing="empty"` (limite documentée, issue #29) ;
- feuille du graphe de dépendances : ne dépend que de `tracing`.

Valeurs rendues : chaîne telle quelle ; booléen en `true`/`false` ; dict
et liste en JSON compact (clés triées) ; autre valeur via `str()`.
"""

from __future__ import annotations

import json
import re
from typing import Any

from tracing import traced

_REFERENCE = re.compile(r"%\{([^{}]+)\}")
_BRACKET_PATH = re.compile(r"\[([^\[\]]+)\]")
_ON_MISSING = ("keep", "empty", "raise")
_MISSING = object()


@traced
def parse_field_path(reference: str) -> list[str]:
    """Découpe une référence de champ en chemin de clés.

    `"host"` → `["host"]` ; `"[host][ip]"` → `["host", "ip"]`.

    Raises:
        ValueError: référence vide ou crochets mal formés.
    """
    ref = reference.strip()
    if not ref:
        raise ValueError("référence de champ vide")
    if not ref.startswith("["):
        if "[" in ref or "]" in ref:
            raise ValueError(f"référence de champ mal formée : {reference!r}")
        return [ref]
    parts = _BRACKET_PATH.findall(ref)
    if not parts or "".join(f"[{p}]" for p in parts) != ref:
        raise ValueError(f"référence de champ mal formée : {reference!r}")
    return parts


@traced
def get_field(doc: dict[str, Any], reference: str, default: Any = None) -> Any:
    """Valeur du champ `reference` dans `doc`, ou `default` s'il est absent."""
    current: Any = doc
    for key in parse_field_path(reference):
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and key.lstrip("-").isdigit() and -len(current) <= int(key) < len(current):
            current = current[int(key)]
        else:
            return default
    return current


def _format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return str(value)


@traced
def render_template(template: str, doc: dict[str, Any], on_missing: str = "keep") -> str:
    """Remplace chaque référence `%{...}` de `template` par la valeur du champ.

    Args:
        template: gabarit, ex. `"%{hostname}-%{[host][ip]}"`.
        doc: document (dict) source des valeurs.
        on_missing: champ absent → `"keep"` laisse la référence telle quelle
            (comportement de Logstash), `"empty"` la remplace par une chaîne
            vide, `"raise"` lève `KeyError`.

    Raises:
        ValueError: `on_missing` inconnu, ou référence mal formée.
        KeyError: champ absent avec `on_missing="raise"`.
    """
    if on_missing not in _ON_MISSING:
        raise ValueError(f"on_missing inconnu : {on_missing!r} (attendu : {list(_ON_MISSING)})")

    def substitute(match: re.Match[str]) -> str:
        value = get_field(doc, match.group(1), _MISSING)
        if value is _MISSING:
            if on_missing == "raise":
                raise KeyError(match.group(1))
            return "" if on_missing == "empty" else match.group(0)
        return _format_value(value)

    return _REFERENCE.sub(substitute, template)
