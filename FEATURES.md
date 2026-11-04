# FEATURES.md — Fonctionnalités et backlog

## Fonctionnalités implémentées

### Pipeline principal
- **rsyslog omprog** — Réception des messages syslog via asyncio
- **confirmMessages="on"** — Accusé de réception rsyslog (re-émission après perte)
- **Format JSON** — Codec JSON rsyslog (rsyslog → omprog → Python)

### Filtres, enrichissement, pipelines `.conf`

Branchés par `omprog.py` (`--filters`, `--enrich-dict`, `--geoip-db`,
`--pipeline-conf`) ; implémentés et documentés dans PyStashTemplate depuis
le découpage #111 : [FEATURES.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/FEATURES.md),
[référence des formats](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/pipeline-logstash.md),
[audit des fonctions Logstash](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/audit-fonctions-logstash.md).

### Indexation, DLQ, métriques, connexion OpenSearch

Branchés par `omprog.py` (`--opensearch-host`, `--index-pattern`,
`--document-id-template`, `--document-id-fingerprint`, `--dlq-*`,
`--metrics-port`, blocs `opensearch{}` du `.conf`) ; implémentés et
documentés dans PyStashTemplate depuis la correction du découpage #111
(#171) : modules `indexer`, `dlq`, `metrics` et `opensearchconf`,
[référence](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md). Le pont garde le préfixe de métriques `rsyslogstach`.

## Items "Proposé" — Statut

| # | Item | Statut | Session |
|---|------|--------|---------|
| 2 | Dead Letter Queue pour échecs permanents | ✅ Fait | 13 |
| 4 | Fingerprint déterministe pour document_id | ✅ Fait | 17 |

## Limites connues

### DLQ
- Rotation/purge : options `--dlq-max-size`, `--dlq-max-age`, `--dlq-backups`, `--dlq-retention`, `--dlq-no-compress` de `omprog.py` (issue #27), appliquées à `pystashtemplate.dlq.LocalDeadLetterQueue`

### Bibliothèque (PyStashTemplate)
- Limites des gabarits, du fingerprint et de l'interpréteur `.conf` : [FEATURES.md de PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/FEATURES.md#limites-connues)
- **Changement de comportement (#49)** : un `document_id`, un nom d'index ou une empreinte construit à partir d'un booléen (`True` → `true`), d'une liste (`['a', 'b']` → `a,b`) ou d'un objet (repr Python → JSON) change de valeur — à signaler dans les notes de version (doublons possibles dans OpenSearch pour les documents déjà indexés avec l'ancien rendu)

### Point d'entrée (omprog.py)
- Reconstruit en 2026 (issue #40) : le fichier d'origine n'a pas été retrouvé
- Sorties `output{}` honorées : `opensearch` et `elasticsearch` (`index`, `document_id`) ; `hosts` du pipeline ignoré (nœuds de `--opensearch-host`)
- `${VAR}` des pipelines `.conf` non substitués (variables d'environnement Logstash)

### Indexation (`pystashtemplate.indexer`)
- **Multi-nœuds (#37, revu par #160)** : la sortie n'utilise que le premier nœud (avertissement si plusieurs) — l'échec rend le message à rsyslog qui le retient ; plus de failover transport. `health()` (GET /) alimente le health check périodique d'omprog (`--health-check-interval`, défaut 300 s, 0 = désactivé) — un échec journalise un warning, sans jamais interrompre le pont
- **Fingerprint HMAC/MURMUR3 (#28)** : `--fingerprint-method murmur3` (entier 32 bits via `mmh3`, non cryptographique, format `_id` décimal) ; mode HMAC avec `--fingerprint-key` ou la variable d'environnement `FINGERPRINT_KEY` (clé de déploiement, `_id` incomparables entre clés ; pas de HMAC MURMUR3, comme le filtre Logstash)
- **`_id` déterministe (#33)** : `--document-id-template` (champ identifiant naturel, lisible) et `--document-id-fingerprint` (hash du contenu, aucun champ naturel) peuvent être configurés **simultanément** — le fingerprint est prioritaire, jamais combinés dans un même `_id` ; sans l'un ni l'autre, `_id` aléatoire (historique). Documentation des cas d'usage dans le README et dans la [référence PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md#identifiant-de-document-_id)

## Backlog

| Item | Priorité | Issue |
|------|----------|-------|
| Packaging package installable | P3 | #31 |
| `--document-id-template` (complément du fingerprint) | P3 | #33 |
| Internationalisation complète | — | #38 |

Terminé : #35 (métriques Prometheus, `--metrics-port`), #34 (filtres avancés : `date` dans `--filters`, `drop {}` natif ; `grok` écarté), #25 (modules manquants + tests), #26 (README), #29 (null distingué d'absent — décision Mathilde), #30 (test d'intégration bout en bout), #31 (packaging installable), #32 (fichiers de suivi), #33 (_id déterministe documenté), #37 (failover multi-nœuds + health check périodique), #28 (fingerprint HMAC + MURMUR3).
