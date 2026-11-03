# Audit des fonctions Logstash utilisables dans les templates

Issue #101. État au 03/11/2026 sur `dev`. Ce tableau recense les fonctions
qu'un pipeline Logstash peut utiliser : gabarits sprintf `%{...}`, conditions,
plugins `filter{}` et `output{}`, options communes. Il indique ensuite ce que
rsyslogstach interprète réellement.

Légende : **fait** = interprété avec le comportement Logstash ; **partiel** =
interprété avec des limites (voir commentaire) ; **pas fait** = accepté par le
parseur mais sans effet sur le document ; **hors périmètre** = sans objet pour
un pont rsyslog → OpenSearch.

Références : [documentation des filtres Logstash](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html),
[références de champs et sprintf](https://www.elastic.co/guide/en/logstash/current/event-dependent-configuration.html),
[plugin logstash-output-opensearch](https://github.com/opensearch-project/logstash-output-opensearch).

## Gabarits sprintf (`src/templates.py`)

| Fonction | Fait / pas fait | Commentaires |
|---|---|---|
| `%{champ}` | fait | Champ de premier niveau. |
| `%{[objet][champ]}` | fait | Un niveau par paire de crochets, profondeur libre. |
| `%{[@metadata][champ]}` | fait | `@metadata` traité comme un champ racine ordinaire. |
| `%{[tableau][0]}` | fait | Indice numérique de tableau. |
| `%{+YYYY.MM.dd}` (Joda) | fait | Date de `@timestamp`, ancienne syntaxe. |
| `%{{yyyy.MM.dd}}` (Java Time) | partiel | Lettres usuelles seulement (y, M, d, H, m, s, S, X/Z, texte entre quotes) ; une lettre inconnue (`E`, `W`…) est recopiée telle quelle. |
| `%{{TIME_NOW}}` | fait | Heure du traitement, pas `@timestamp`. |
| `%{+%s}` (epoch) | fait | Secondes depuis l'epoch de `@timestamp` (corrigé par #102 : rendait `%0`). |
| Champ absent | fait | `--pipeline-on-missing` / `--filters-on-missing` : `keep` conserve `%{...}`, `empty` rend une chaîne vide. Un champ `null` se rend vide. |
| Valeur hash ou tableau dans `%{...}` | fait | Rendue en JSON compact. |
| Échappement de crochets dans un nom de champ (`none`/`percent`/`ampersand`) | pas fait | Cas non rencontré dans les logs visés. |
| `${VAR}` / `${VAR:défaut}` (variables d'environnement du `.conf`) | pas fait | Le texte est gardé littéralement. Sans effet aujourd'hui sur la connexion, qui vient de la ligne de commande, mais un `index => "${X}-%{+YYYY}"` serait rendu tel quel. |

## Conditions `if` / `else if` / `else` (`src/interpreter.py`)

| Fonction | Fait / pas fait | Commentaires |
|---|---|---|
| `if [champ]` (présence) | fait | Absent, `null` ou `false` → faux ; chaîne vide et `0` → vrai, comme Logstash. |
| `==`, `!=`, `<`, `<=`, `>`, `>=` | fait | Un opérande absent n'est égal à rien (`!=` vrai, le reste faux). |
| `=~`, `!~` (regex) | fait | Expression régulière Python. |
| `in`, `not in` | fait | Sous-chaîne si la cible est une chaîne, appartenance si c'est un tableau. |
| `and`, `or`, `xor`, `nand` | fait | Sans court-circuit. |
| `!` (négation), parenthèses | fait | |
| `else if` en chaîne, `if` imbriqués | fait | Dans `filter{}` comme dans `output{}`. |

## Plugins `filter{}`

| Plugin | Fait / pas fait | Commentaires |
|---|---|---|
| `mutate` | fait | Ordre officiel : `coerce`, `rename`, `update`, `replace`, `convert`, `gsub`, `uppercase`, `capitalize`, `lowercase`, `strip`, `split`, `join`, `merge`, `copy`, puis options communes. `tag_on_failure` (défaut `_mutate_error`). |
| `dissect` | partiel | `mapping` seulement ; `convert_datatype` et `tag_on_failure` non lus. |
| `date` | partiel | `match` (ISO8601, UNIX, UNIX_MS, motifs Joda), `target`, `timezone`, `tag_on_failure`. Pas de `SSS` (millisecondes) ni de fuseau textuel (`z`, « CET »). `locale` non lu. |
| `geoip` | partiel | `source`, `target`, `fields`, `tag_on_failure`. `database` obligatoire (pas de base GeoLite2 embarquée). |
| `translate` | partiel | `source`, `target`, `dictionary_path` (YAML), `fallback` (gabarit sprintf). Non lus : `dictionary` en ligne, `exact`, `regex`, `override`, `refresh_behaviour`, `iterate_on`. |
| `drop` | fait | `percentage` compris. |
| `grok` | pas fait | Remplacé par un step `regex` à groupes nommés dans `--filters`, ou appelé via `filters_json`. |
| `kv` | pas fait | Disponible dans `--filters` (step `kv`) et via `filters_json`, pas en bloc natif. |
| `json` | oui | Bloc `filter{}` natif (#115) : `source`, `target` (sinon fusion à la racine), `skip_on_invalid_json`, `tag_on_failure` (défaut `_jsonparsefailure`). `@timestamp` décodé n'est pas converti en date. |
| `dns` | pas fait | Présent dans `pipeline.example.d/25_filter_…` : bloc ignoré (trace de débogage). |
| `fingerprint` | partiel | Pas en bloc `filter{}` ; équivalent côté indexation : `--document-id-fingerprint`, `--fingerprint-method`, `--fingerprint-key`. |
| `useragent`, `csv`, `cidr`, `clone`, `split`, `aggregate`, `prune`, `urldecode`, `uuid`, `syslog_pri`, `truncate`, `xml`, `ruby`, `elapsed`, `throttle`, `memcached`, `http`, `jdbc_*` | pas fait | Blocs acceptés par le parseur, sans effet. |
| `mmdb` (communautaire) | fait | Extension hors cœur Logstash : `database`, `source`, `target`. |
| `filters_json` (propre au projet) | fait | Invoque un fichier `--filters` depuis un `.conf`. |

## Options communes à tous les filtres

| Option | Fait / pas fait | Commentaires |
|---|---|---|
| `add_field`, `remove_field`, `add_tag`, `remove_tag` | fait | Après tout filtre natif réussi (`mutate`, `dissect`, `date`, `geoip`, `translate`, `mmdb`), jamais après un échec, comme `filter_matched` (#116). |
| `id`, `enable_metric`, `periodic_flush` | hors périmètre | Sans effet sur le document. |

## Plugins et options `output{}`

| Fonction | Fait / pas fait | Commentaires |
|---|---|---|
| `opensearch { … }` / `elasticsearch { … }` | partiel | Seules `index` et `document_id` (gabarits sprintf) sont lues par document. |
| `hosts`, `user`, `password`, `ssl`, `ssl_certificate_verification` | pas fait dans le `.conf` | Fournis par `--opensearch-host`, `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD` et `--no-verify-certs`. |
| `cacert`, `tls_certificate`, `tls_key` (mTLS) | fait (ligne de commande) | Mêmes noms que le plugin logstash-output-opensearch : `--cacert`, `--tls-certificate`, `--tls-key` (#100). Lus sur la ligne de commande, pas dans le `.conf`, comme `hosts`. |
| `keystore`, `truststore` (JKS / PKCS#12) | pas fait | Format Java ; utiliser des fichiers PEM. |
| `action`, `pipeline`, `routing`, `ilm_*`, `template*` | pas fait | `action` vaut toujours `index` ; le template d'index passe par `--index-template`. |
| `stdout`, `file`, `http`, autres sorties | pas fait | Ignorées (trace de débogage). |

## Sections `input{}`

| Fonction | Fait / pas fait | Commentaires |
|---|---|---|
| `input { … }` | hors périmètre | Parsé mais jamais exécuté : l'entrée est rsyslog (omprog). |
