"""Garde-fou de docs/opensearch-index-schema.md (issue #36).

Chaque champ déclaré dans opensearch-index-template.json (y compris les
sous-champs de `geoip`) doit avoir sa ligne dans le tableau « Champs
déclarés », avec le même type, et inversement : la documentation ne peut
pas dériver du template sans que la suite échoue.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "opensearch-index-template.json"
DOC = ROOT / "docs" / "opensearch-index-schema.md"


def _template_fields() -> dict[str, str]:
    props = json.loads(TEMPLATE.read_text(encoding="utf-8"))["template"]["mappings"]["properties"]
    fields: dict[str, str] = {}

    def walk(prefix: str, mapping: dict) -> None:
        for name, spec in mapping.items():
            full = f"{prefix}{name}"
            fields[full] = spec.get("type", "object")
            if "properties" in spec:
                walk(f"{full}.", spec["properties"])

    walk("", props)
    return fields


def _documented_fields() -> dict[str, str]:
    section = DOC.read_text(encoding="utf-8").split("### Champs déclarés", 1)[1].split("\n### ", 1)[0]
    rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)`", section, re.M)
    return dict(rows)


def test_chaque_champ_du_template_est_documente() -> None:
    assert sorted(set(_template_fields()) - set(_documented_fields())) == []


def test_aucun_champ_documente_absent_du_template() -> None:
    assert sorted(set(_documented_fields()) - set(_template_fields())) == []


def test_types_documentes_identiques() -> None:
    template, doc = _template_fields(), _documented_fields()
    assert {k: (template[k], doc[k]) for k in template if k in doc and template[k] != doc[k]} == {}


def test_motif_d_index_documente() -> None:
    patterns = json.loads(TEMPLATE.read_text(encoding="utf-8"))["index_patterns"]
    text = DOC.read_text(encoding="utf-8")
    for pattern in patterns:
        assert f"`{pattern}`" in text


def test_exemples_json_valides() -> None:
    blocks = re.findall(r"```json\nGET [^\n]+\n(.*?)```", DOC.read_text(encoding="utf-8"), re.S)
    assert len(blocks) >= 5
    for block in blocks:
        json.loads(block)
