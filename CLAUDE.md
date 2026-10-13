# CLAUDE.md — Contexte projet rsyslogstach

## Description

**rsyslogstach** — Pont rsyslog → omprog (asyncio) → OpenSearch, compatible schéma/filtres Logstash.

Pipeline asynchrone en Python qui reçoit les messages syslog via le module `omprog` de rsyslog, applique des filtres (drop, regex, kv, mutate, geoip) et un enrichissement (dictionnaire statique, GeoIP), puis indexe dans OpenSearch avec une Dead Letter Queue pour les échecs permanents et un fingerprint déterministe pour l'idempotence.

## Stack technique

- Python >= 3.11, asyncio
- opensearch-py[async] (indexation asynchrone)
- geoip2 / maxminddb (enrichissement GeoIP)
- pyyaml (configuration)
- logstash-pipeline-parser==0.0.3 (parsing des pipelines .conf Logstash)
- loguru (journalisation)

## Architecture des modules

```
src/
├── omprog.py          Point d'entrée asyncio (rsyslog omprog)
├── tracing.py         Décorateur @traced (entrée/sortie loguru) — AUCUNE dépendance interne
├── util.py            Utilitaires : add_failure_tags, load_json_file, opensearch_auth_from_env — dépend de tracing
├── templates.py       render_template() — syntaxe %{field} / %{[a][b]} — dépend de tracing
├── fingerprint.py     compute_fingerprint() — sha256/sha1/md5 — dépend de templates, tracing
├── dlq.py             LocalDeadLetterQueue — JSONL append-only — dépend de tracing
├── enrichment.py      Enrichissement par dictionnaire + GeoIP — dépend de templates, tracing
├── filters.py         FilterPipeline (drop, regex, kv, mutate, geoip) — dépend de util, enrichment, tracing
├── interpreter.py     PipelineInterpreter (--pipeline-conf) — dépend de filters, util, tracing
└── indexer.py         OpenSearchIndexer — dépend de util, dlq, tracing
```

### Graphe de dépendances (acyclique, vérifié par tests/test_no_cross_imports.py)

```
tracing (feuille)
    ↑
util, templates, dlq (feuilles)
    ↑
fingerprint (→ templates), enrichment (→ templates)
    ↑
filters (→ util, enrichment), indexer (→ util, dlq)
    ↑
interpreter (→ filters, util)
    ↑
omprog (point d'entrée)
```

## Conventions

- **Traçabilité systématique** : toute fonction de `src/` est décorée par `@traced` (entrée + sortie, y compris exceptions). Jamais d'arguments dans les logs (risque de fuite de secrets via `credentials`).
- **Absence de dépendances circulaires** : vérifiée mécaniquement par `tests/test_no_cross_imports.py` (analyse `ast`, pas de simple relecture).
- **Tests sans pytest-asyncio** : `asyncio.run()` direct (voir `test_dlq.py`, `test_indexer.py`).
- **Secrets en environnement** : `opensearch_auth_from_env()` lit `OPENSEARCH_USER`/`OPENSEARCH_PASSWORD` (jamais en argument CLI, visible via `ps aux`).
- **Package à plat** : `src/*.py` sans `__init__.py`, importé via `sys.path` (voir `conftest.py`).

## Historique des sessions

- **Session 1** — Démarrage, choix de la stack
- **Session 2** — Compatibilité schéma/filtres Logstash
- **Session 3** — Indexation OpenSearch async
- **Session 4** — Migration threads → asyncio
- **Session 5** — Module templates
- **Session 6** — Module enrichment
- **Session 7** — Pipeline interpreter (--pipeline-conf)
- **Session 8** — Module filters (--filters)
- **Session 9** — Réorganisation squelette + --document-id-template
- **Session 10** — Tests unitaires indexer
- **Session 11** — Tests unitaires templates
- **Session 12** — Tests unitaires filters
- **Session 13** — Dead Letter Queue (DLQ) — FEATURES.md "Proposé" #2
- **Session 14** — Filtre mutate (convert, remove_field, prefix)
- **Session 15** — Tests unitaires enrichment
- **Session 16** — Tests unitaires interpreter
- **Session 17** — Fingerprint — FEATURES.md "Proposé" #4
- **Session 18** — Modules consommateurs de util
- **Session 19** — _date_parse_failure + tag_on_failure
- **Session 20** — Options mutate (uppercase/lowercase/capitalize/split/join/merge/copy/update/coerce)
- **Session 21** — _build_geoip_record partagé
- **Session 22** — Extraction de _add_failure_tags
- **Session 23** — Tests no cross imports (ast)
- **Session 24** — GeoipFilter + util.add_failure_tags

## Instructions reçues dans le chat (issue #51)

Toute instruction reçue dans le chat (Perplexity Computer, Claude Code ou autre) devient une issue. Une phrase ne reste pas en l'air.

- Avant de commencer le travail, créer l'issue dans le dépôt concerné, en citant l'instruction mot pour mot avec sa date.
- Une demande qui touche plusieurs dépôts donne une issue par dépôt, chacune liée aux autres.
- Une question posée dans le chat sans réponse immédiate devient elle aussi une issue, ou un commentaire « Question pour Mathilde » sur l'issue existante.
- La PR ferme ou cite l'issue (`Closes #n`). Une instruction abandonnée est fermée avec sa raison (« not planned »).
- En fin de session, vérifier que chaque instruction du chat a son issue, ouverte ou fermée.
