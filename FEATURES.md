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
| **mutate** | convert (integer, integer_eu, float, float_eu, string, boolean ; règles de la documentation Logstash, issue #73), remove_field, prefix | 14 |
| **mutate** | uppercase, lowercase, capitalize, split, join, merge, copy, update, coerce | 20 |
| **geoip** | source, target, tag_on_failure | 24 |
| **date** | match (ISO8601, UNIX, UNIX_MS, motif Java/Joda), target, timezone, tag_on_failure ; même implémentation que le plugin `date` des `.conf` | #34 |

### Enrichissement (module enrichment.py)
- Dictionnaire statique JSON (`enrich-dict.example.json`)
- GeoIP via geoip2/maxminddb (`_build_geoip_record`, session 21)

### Pipeline Logstash (module interpreter.py, --pipeline-conf)
- Parsing des fichiers `.conf` via `logstash-pipeline-parser`
- Exemples : `pipeline.example.d/10_input`, `25_filter`, `30_output`
- tag_on_failure pour date et geoip (sessions 19, 22, 24)
- Filtres natifs interprétés : `dissect`, `mutate`, `translate` (toutes les options du plugin, #119), `mmdb`, `geoip`, `date`, `drop` (avec `percentage`, #34), `kv` (#113), `fingerprint` (#114), `grok` (#112), `useragent`, `xml` et `dns` (#121), plus le pont `filters_json`

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
- Rotation/purge : options `--dlq-max-size`, `--dlq-max-age`, `--dlq-backups`, `--dlq-retention`, `--dlq-no-compress` de `omprog.py` (issue #27)

### Fingerprint (fingerprint.py)
- Pas de mode HMAC (nécessiterait une clé secrète)
- Pas de MURMUR3 (entier 32 bits, format _id différent)
- Pas de IPV4_NETWORK (portée trop spécifique)
- Voir issue #28

### Templates (templates.py)
- Fraction de seconde `S…` : précision microseconde ; au-delà de 6 lettres, complétée par des zéros (`SSSSSSSSS` → `123456000`) (#123)
- Lettres de date (#123) : Java Time dans `%{{…}}` (`G u y Y Q q M L w W D d E e c a h K k H m s S n N A V O X x Z z`) et Joda dans `%{+…}` (`G C Y x y w e E M D d a h K k H m s S Z z`) ; semaines ISO (lundi, semaine 1 d'au moins 4 jours) et textes en anglais, alors que Java Time suit la locale de la JVM ; `F` et `B` recopiées telles quelles
- Rendu des valeurs aligné sur Logstash 8 (`StringInterpolation`, issue #49) : booléen `true`/`false`, liste jointe par `,`, objet en JSON compact
- **Changement de comportement (#49)** : un `document_id`, un nom d'index ou une empreinte construit à partir d'un booléen (`True` → `true`), d'une liste (`['a', 'b']` → `a,b`) ou d'un objet (repr Python → JSON) change de valeur — à signaler dans les notes de version (doublons possibles dans OpenSearch pour les documents déjà indexés avec l'ancien rendu)
- Références mal formées refusées (`ValueError`) comme par Logstash : `a[b]`, `a]`, `[]`, `[a[b]]`
- Écart assumé : un objet à l'intérieur d'une liste est rendu en JSON (Logstash utilise le `toString()` Java de la map)
- Rendu d'un champ `null` : chaîne vide — écart assumé avec Logstash 8, qui conserve le gabarit `%{champ}` littéral. **Fingerprint (#29, décision Mathilde)** : un champ `null` est distingué d'un champ absent — il compte comme présent (empreinte du contenu vide), `None` uniquement si tous les champs demandés sont absents

### Pipeline `.conf` (interpreter.py)
- Plugins natifs non interprétés (structure seule, signalée en debug) : `aggregate`, `ruby`… Leur équivalent passe par `filters_json` quand il existe
- Décision #34, revue par #112 (`grok` natif livré) : à l'époque, `grok` n'était pas implémenté. Un step `regex` à groupes nommés (`(?P<champ>...)`) fait le même travail sans embarquer la bibliothèque de motifs grok. `dissect` (natif et JSON) et `translate` (natif et JSON) étaient déjà couverts. `date` est désormais disponible des deux côtés
- Comme Logstash, un tableau à un seul élément dans une condition (`[level] in ["ERROR"]`) est une **référence de champ**, pas un tableau : écrire `[level] == "ERROR"` ou au moins deux éléments
- `mutate convert` : une chaîne non numérique (« abc ») laisse le champ inchangé (Logstash/Ruby donnerait 0)

### Point d'entrée (omprog.py)
- Reconstruit en 2026 (issue #40) : le fichier d'origine n'a pas été retrouvé
- Sorties `output{}` honorées : `opensearch` et `elasticsearch` (`index`, `document_id`) ; `hosts` du pipeline ignoré (nœuds de `--opensearch-host`)
- `${VAR}` des pipelines `.conf` non substitués (variables d'environnement Logstash)

### Indexer (indexer.py)
- Réponse du serveur aux redirections (imprimante/série/parallèle) traitée côté serveur, jamais remontée à l'API
- **Multi-nœuds et failover (#37)** : le transport opensearch-py retente le nœud suivant en cas d'échec de connexion ; `retry_on_timeout=True` étend le repli aux délais d'attente (défaut de la bibliothèque : False). `health()` (GET /) alimente le health check périodique d'omprog (`--health-check-interval`, défaut 300 s, 0 = désactivé) — un échec journalise un warning, sans jamais interrompre le pont
- **Fingerprint HMAC/MURMUR3 (#28)** : `--fingerprint-method murmur3` (entier 32 bits via `mmh3`, non cryptographique, format `_id` décimal) ; mode HMAC avec `--fingerprint-key` ou la variable d'environnement `FINGERPRINT_KEY` (clé de déploiement, `_id` incomparables entre clés ; pas de HMAC MURMUR3, comme le filtre Logstash)
- **`_id` déterministe (#33)** : `--document-id-template` (champ identifiant naturel, lisible) et `--document-id-fingerprint` (hash du contenu, aucun champ naturel) peuvent être configurés **simultanément** — le fingerprint est prioritaire, jamais combinés dans un même `_id` ; sans l'un ni l'autre, `_id` aléatoire (historique). Documentation des cas d'usage dans le README

## Backlog

| Item | Priorité | Issue |
|------|----------|-------|
| Packaging package installable | P3 | #31 |
| `--document-id-template` (complément du fingerprint) | P3 | #33 |
| Internationalisation complète | — | #38 |

Terminé : #35 (métriques Prometheus, `--metrics-port`), #34 (filtres avancés : `date` dans `--filters`, `drop {}` natif ; `grok` écarté), #25 (modules manquants + tests), #26 (README), #29 (null distingué d'absent — décision Mathilde), #30 (test d'intégration bout en bout), #31 (packaging installable), #32 (fichiers de suivi), #33 (_id déterministe documenté), #37 (failover multi-nœuds + health check périodique), #28 (fingerprint HMAC + MURMUR3).
