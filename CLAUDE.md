# CLAUDE.md — Contexte projet rsyslogstach


## Mission

Avant toute intervention autonome sur ce dépôt : lire et appliquer la
mission d'équipe :
https://github.com/Mathilde-Team/.github/blob/dev/MISSION.md
(le socle qualité, SOCLE.md, prime sur la mission en cas de conflit ; si
le fichier est absent sur `dev`, le chercher sur `main`).

## Description

**rsyslogstach** — Pont rsyslog → omprog (asyncio) → OpenSearch, compatible schéma/filtres Logstash.

Connecteur rsyslog asynchrone en Python : il reçoit les messages syslog via le module `omprog` de rsyslog, leur applique filtres, enrichissement et pipelines `.conf` Logstash **via la bibliothèque [PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate)** (découpage #111), puis indexe dans OpenSearch avec une Dead Letter Queue pour les échecs permanents et un fingerprint déterministe pour l'idempotence.

Découpage #111 corrigé (#171) : seul `omprog`, propre à rsyslog, reste ici. Ce qui relève de la sémantique Logstash (gabarits, filtres, interpréteur, enrichissement, grok, fingerprint, sorties) et de la livraison (indexer, DLQ, métriques, options de connexion OpenSearch) se développe et se documente dans PyStashTemplate ([FEATURES.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/FEATURES.md), [PATTERNS.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/PATTERNS.md)) ; les issues correspondantes s'ouvrent dans ce dépôt-là.

## Stack technique

- Python >= 3.11, asyncio
- pystashtemplate v0.3.0, tag git figé (gabarits, filtres, `.conf`, enrichissement GeoIP/DNS, sorties, `indexer`, `dlq`, `metrics`, `opensearchconf` — et leurs propres dépendances : logstash-pipeline-parser, geoip2/maxminddb, ua-parser, lxml, dnspython, prometheus-client…)
- loguru (journalisation)

## Architecture des modules

```
src/
├── omprog.py   Point d'entrée asyncio (protocole rsyslog omprog) — dépend de i18n + pystashtemplate
└── i18n.py     Domaine gettext `rsyslogstach` — dépend de pystashtemplate.tracing
```

`indexer`, `dlq`, `metrics` et `opensearchconf` sont importés de `pystashtemplate.*` (voir [docs/indexation-metriques.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md)).

### Graphe de dépendances (acyclique, vérifié par tests/test_no_cross_imports.py)

```
pystashtemplate (dépendance externe)
    ↑
i18n
    ↑
omprog (point d'entrée)
```

## Conventions

- **Traçabilité systématique** : toute fonction de `src/` est décorée par `@traced` de `pystashtemplate.tracing` (entrée + sortie, y compris exceptions). Jamais d'arguments dans les logs (identifiants OpenSearch, clé HMAC).
- **Absence de dépendances circulaires** : vérifiée mécaniquement par `tests/test_no_cross_imports.py` (analyse `ast`, pas de simple relecture).
- **Tests sans pytest-asyncio** : `asyncio.run()` direct (voir `test_omprog.py`).
- **Secrets en environnement** : `pystashtemplate.util.opensearch_auth_from_env()` lit `OPENSEARCH_USER`/`OPENSEARCH_PASSWORD` (jamais en argument CLI, visible via `ps aux`).
- **Package à plat** : `src/*.py` sans `__init__.py`, importé via `sys.path` (voir `conftest.py`).

## Historique des sessions

Les sessions 3 et 5 à 24 portent sur des modules partis dans PyStashTemplate au découpage #111 et à sa correction #171 (templates, enrichment, interpreter, filters, fingerprint, util, tracing, indexer, dlq).

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
