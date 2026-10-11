# FEATURES.md — Fonctionnalités et backlog

## Fonctionnalités implémentées

### Pipeline principal
- **rsyslog omprog** — Réception des messages syslog via asyncio
- **confirmMessages="on"** — Accusé de réception rsyslog (re-émission après perte)
- **Format JSON** — Codec JSON rsyslog (rsyslog → omprog → Python)

### Filtres (module filters.py, --filters)
| Filtre | Options | Session |
|--------|---------|---------|
| **drop** | source, words_file, mode (contains), case_sensitive | 8 |
| **regex** | source, pattern (groupes nommés) | 8 |
| **kv** | source, field_split, value_split, prefix | 8 |
| **mutate** | convert (integer/string), remove_field, prefix | 14 |
| **mutate** | uppercase, lowercase, capitalize, split, join, merge, copy, update, coerce | 20 |
| **geoip** | source, target, tag_on_failure | 24 |

### Enrichissement (module enrichment.py)
- Dictionnaire statique JSON (`enrich-dict.example.json`)
- GeoIP via geoip2/maxminddb (`_build_geoip_record`, session 21)

### Pipeline Logstash (module interpreter.py, --pipeline-conf)
- Parsing des fichiers `.conf` via `logstash-pipeline-parser`
- Exemples : `pipeline.example.d/10_input`, `25_filter`, `30_output`
- tag_on_failure pour date et geoip (sessions 19, 22, 24)

### Indexation OpenSearch (module indexer.py)
- `OpenSearchIndexer` — indexation asynchrone (opensearch-py[async])
- Authentification via variables d'environnement
- Template d'index (`opensearch-index-template.json`)
- Retenue (retry) sur erreurs transitoires (connexion refusée, timeout)

### Dead Letter Queue (module dlq.py, session 13)
- `LocalDeadLetterQueue.write()` — JSONL append-only
- Uniquement pour erreurs permanentes (RequestError/NotFoundError, 400/404)
- Jamais pour erreurs transitoires (retenue inchangée)
- Écriture dans thread séparé (`asyncio.to_thread`)
- Rotation par taille (`max_bytes`) ou par âge de la plus ancienne entrée (`max_age`), compression gzip, purge par nombre (`backups`) et par âge (`retention`), `parse_size`/`parse_duration` pour les options CLI (issue #27)

### Fingerprint (module fingerprint.py, session 17)
- `compute_fingerprint()` — sha256/sha1/md5
- Document entier (fields=None/[]) ou sélection ordonnée de champs
- Séparateur de contrôle `\x1f` anti-collision
- `None` si tous les champs demandés sont absents

### Traçabilité (module tracing.py)
- Décorateur `@traced` — entrée/sortie systématique (loguru)
- Préserve `__name__`/`__doc__`/`__wrapped__` (functools.wraps)
- Compatible méthodes GObject/GTK4

## Items "Proposé" — Statut

| # | Item | Statut | Session |
|---|------|--------|---------|
| 2 | Dead Letter Queue pour échecs permanents | ✅ Fait | 13 |
| 4 | Fingerprint déterministe pour document_id | ✅ Fait | 17 |

## Limites connues

### DLQ (dlq.py)
- Rotation/purge disponibles dans `dlq.py` (issue #27) ; options `--dlq-*` à câbler dans `omprog.py` une fois le module importé (#25/#40)

### Fingerprint (fingerprint.py)
- Pas de mode HMAC (nécessiterait une clé secrète)
- Pas de MURMUR3 (entier 32 bits, format _id différent)
- Pas de IPV4_NETWORK (portée trop spécifique)
- Voir issue #28

### Templates (templates.py)
- Champ `null` traité comme absent (se rend en chaîne vide)
- Voir issue #29

### Indexer (indexer.py)
- Réponse du serveur aux redirections (imprimante/série/parallèle) traitée côté serveur, jamais remontée à l'API

## Backlog

| Item | Priorité | Issue |
|------|----------|-------|
| Pousser les modules manquants | P0 | #25 |
| Écrire le README | P1 | #26 |
| DLQ rotation/purge — options CLI dans omprog.py | P3 | #27 |
| Fingerprint HMAC/MURMUR3 | P3 | #28 |
| Templates null vs absent | P2 | #29 |
| Test d'intégration bout en bout | P2 | #30 |
| Packaging package installable | P3 | #31 |
| Pousser fichiers de suivi | P0 | #32 |
