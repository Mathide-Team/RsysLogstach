# rsyslogstach

**Pont rsyslog → omprog (asyncio) → OpenSearch, compatible schéma/filtres Logstash.**

Pipeline asynchrone en Python qui reçoit les messages syslog via le module `omprog` de rsyslog, applique des filtres et un enrichissement, puis indexe dans OpenSearch — avec Dead Letter Queue pour les échecs permanents et fingerprint déterministe pour l'idempotence.

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![License: GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

## Architecture

```
rsyslog → omprog (asyncio) → [filters] → [enrichment] → [indexer] → OpenSearch
                                      ↓                        ↓
                                  blocklist               DLQ (erreurs 4xx)
                                  geoip                   fingerprint (_id)
```

### Modules

| Module | Rôle | Dépendances |
|--------|------|-------------|
| `omprog.py` | Point d'entrée asyncio (rsyslog omprog) | interpreter, indexer |
| `tracing.py` | Décorateur `@traced` (loguru) | — |
| `util.py` | `add_failure_tags`, `load_json_file`, `opensearch_auth_from_env` | tracing |
| `templates.py` | `render_template()` — syntaxe `%{field}` / `%{[a][b]}` | tracing |
| `fingerprint.py` | `compute_fingerprint()` — sha256/sha1/md5 | templates, tracing |
| `dlq.py` | `LocalDeadLetterQueue` — JSONL append-only | tracing |
| `enrichment.py` | Enrichissement dictionnaire + GeoIP | templates, tracing |
| `filters.py` | `FilterPipeline` (drop, regex, kv, mutate, geoip) | util, enrichment, tracing |
| `interpreter.py` | `PipelineInterpreter` (`--pipeline-conf` Logstash) | filters, util, tracing |
| `indexer.py` | `OpenSearchIndexer` (opensearch-py async) | util, dlq, tracing |

Le graphe de dépendances est acyclique, vérifié mécaniquement par `tests/test_no_cross_imports.py` (analyse `ast`).

## Installation

```bash
uv sync                    # environnement isolé
pip install -r requirements.txt  # ou installation classique
```

### Dépendances système

- Python >= 3.11
- OpenSearch (cluster)
- MaxMind GeoIP2 Database (pour le filtre geoip)
- rsyslog avec module omprog

## Configuration

### rsyslog.conf

```conf
module(load="omprog")
action(type="omprog"
    binary="/path/to/src/omprog.py"
    confirmMessages="on"
    template="RSYSLOG_DebugFormat")
```

### Filtres (`--filters`)

Voir `filters.example.json` :

```json
[
  {"type": "drop", "source": "msg", "words_file": "/etc/omprog/blocklist.txt", "mode": "contains"},
  {"type": "regex", "source": "msg", "pattern": "^%%\\d+(?P<module>[A-Z_]+)/..."},
  {"type": "kv", "source": "detail", "field_split": " ", "value_split": "=", "prefix": "kv_"},
  {"type": "mutate", "convert": {"severity_code": "integer"}, "remove_field": ["msg"]}
]
```

### Enrichissement (`enrich-dict.example.json`)

```json
{
  "sw-core-01": {"site": "Besançon - DR", "role": "core", "owner_team": "Infra Réseau"}
}
```

### Pipeline Logstash (`--pipeline-conf`)

Voir `pipeline.example.d/` : input UDP → filter (DNS, GeoIP) → output OpenSearch.

### Index OpenSearch

Template : `opensearch-index-template.json` (index pattern `switch-logs-*`).

## Utilisation

```bash
PYTHONPATH=src python3 src/omprog.py \
    --filters /etc/omprog/filters.json \
    --enrich-dict /etc/omprog/enrichment.json \
    --pipeline-conf /etc/omprog/pipeline.d/ \
    --opensearch-host https://localhost:9200 \
    --index-template opensearch-index-template.json \
    --dlq-path /var/log/rsyslogstach/dlq.jsonl
```

### Rotation de la DLQ (issue #27)

`LocalDeadLetterQueue` sait rotater et purger son fichier JSONL ; tout est
désactivé par défaut (un seul fichier qui grandit, comme avant).

| Paramètre (`dlq.py`) | Option prévue (`omprog.py`) | Effet |
|---|---|---|
| `max_bytes` | `--dlq-max-size 100M` (`parse_size`) | Rotation avant qu'une écriture dépasse cette taille |
| `max_age` | `--dlq-max-age 7d` (`parse_duration`) | Rotation quand la plus ancienne entrée dépasse cet âge |
| `backups` | `--dlq-backups 10` | Fichiers rotatés conservés au maximum |
| `retention` | `--dlq-retention 30d` (`parse_duration`) | Âge maximal d'un fichier rotaté |
| `compress` | `--dlq-no-compress` | Fichiers rotatés en gzip (défaut) |

Fichiers rotatés : `dlq.jsonl.20261010T120000Z.gz` (puis `-1`, `-2`... dans
la même seconde), relisibles avec `zcat`. Le câblage des options dans
`omprog.py` attend l'import de ce module (#25/#40).

### Authentification OpenSearch

```bash
export OPENSEARCH_USER=admin
export OPENSEARCH_PASSWORD=secret
```

## Tests

```bash
uv run pytest tests/ -v
uv run ruff check src/ tests/
```

## Suivi

- **Sessions :** Issues #1–#24 (fermées)
- **Travaux restants :** Issues #25–#32 (ouvertes)
- **FEATURES.md :** Statut des fonctionnalités et backlog
- **PATTERNS.md :** Conventions et patterns
- **CLAUDE.md :** Contexte projet et historique
