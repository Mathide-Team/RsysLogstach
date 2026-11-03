# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Les numéros suivent [SemVer](https://semver.org/lang/fr/), et la version de `pyproject.toml` est égale au tag.

## [Non publié]

- CI et publication : repli GitHub autorisé, publication manuelle sur un tag
  déjà livré dans main, vérification d’ascendance et archives du tag exact.


### Corrigé
- **Chaînes des `.conf`** (#128) : les antislashs entre guillemets sont conservés, comme Logstash (`config.support_escapes: false`) — `"a\.b"` vaut `a\.b` et `"\d+"` vaut `\d+`, au lieu d'être retirés par `logstash-pipeline-parser`. Les regex de `gsub` et des conditions `=~ "..."` redeviennent fidèles ; prérequis des motifs `grok` (#112).
- **Gabarits** (#102) : `%{+%s}` rend les secondes depuis l'epoch de `@timestamp`, comme Logstash, au lieu de `%0`.

### Modifié
- **Licence** (#91) : passage de MIT à GPL-3.0-or-later. `LICENSE` contient désormais le texte officiel de la GPLv3 ; s'y ajoutent `license` dans `pyproject.toml`, les en-têtes SPDX, la section Licence du README avec les licences des dépendances, et `tests/test_licence.py`.

### Ajouté
- Sorties `opensearch` (#126) : `action` (`index`, `create`, `update`,
  `delete`), `pipeline`, `routing` et `doc_as_upsert`, en gabarits sprintf.
- `--field-reference-escape-style` (#124) : crochets échappés (`percent`,
  `ampersand`) dans les noms de champs, comme `field_reference.escape_style`.
- **Connexion OpenSearch dans le `.conf`** (#125) : `hosts`, `user`, `password`, `ssl`, `ssl_certificate_verification`, `cacert`, `tls_certificate` et `tls_key` sont lus dans les blocs `opensearch{}` / `elasticsearch{}` de `output{}`, branches comprises. Sans schéma, une URL de `hosts` est en `http` sauf `ssl => true` (défaut Logstash). La ligne de commande et `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD` restent prioritaires ; des valeurs différentes d'un bloc à l'autre, `ssl` contraire au schéma ou une variable `${VAR}` non remplacée bloquent le démarrage.
- **Gabarits de date** (#123) : lettres Java Time manquantes dans `%{{…}}` (`G`, `u`, `Y`, `Q`/`q`, `MMM`/`MMMM`, `L`, `w`, `W`, `D`, `E`, `e`, `c`, `a`, `h`, `K`, `k`, `n`, `N`, `A`, `VV`, `O`) et lettres Joda propres à `%{+…}` (`C`, `x`, `e`, `E`, `MMM`). `S…` affiche désormais les microsecondes (`SSSSSS` → `123456` au lieu de `123000`).
- **`dns` natif** (#121) dans les `.conf` : `resolve`, `reverse`, `action` (`append`/`replace`), `hostsfile`, `nameserver` (chaîne, liste ou hash `address`/`search`/`ndots`), `timeout`, `max_retries`, `tag_on_timeout`, caches des succès et des échecs avec durée de vie, noms IDNA. `RSYSLOGSTACH_DNS=off` coupe les requêtes réseau.
- **`xml` natif** (#121) dans les `.conf` : `store_xml` (conversion façon XmlSimple, comme Logstash), `xpath` avec `namespaces` et `remove_namespaces`, `parse_options`, `force_array`, `force_content`, `suppress_empty`, tag `_xmlparsefailure`. Entités externes, DTD et XInclude jamais actifs.
- **`useragent` natif** (#121) dans les `.conf` : analyse ua-parser (motifs uap-core), champs ECS (`[user_agent][name]`, `[version]`, `[device][name]`, `[os][name|version|full]`, détail des versions dans `[@metadata][filter][user_agent]`) ou anciens champs avec `ecs_compatibility => disabled` et `prefix`, options `target`, `regexes`, `lru_cache_size`.
- **Plugin `date` : millisecondes, fuseaux textuels et `locale`** (#118) : `SSS` (via `%f`, qui met à l'échelle pareil : « 123 » → 123 ms), noms de fuseaux `z`/`zz`/`zzz`/`ZZZ` (« CET » → +01:00, IDs IANA « Europe/Paris » via `ZoneInfo` ; abréviations réduites aux zones européennes et nord-américaines courantes) et option `locale` (`fr` : noms de mois/jours traduits vers l'anglais avant `strptime`, sans `setlocale` global). Le fuseau textuel trouvé dans la valeur prime sur `timezone`, comme un fuseau explicite.
- **`translate` complet** (#119), dans les `.conf` et le step `translate` de `--filters` (une seule implémentation, `filters.TranslateFilter`) : `dictionary` en ligne, dictionnaires JSON et CSV en plus du YAML, `exact`, `regex`, `override`, `iterate_on` (tableau de valeurs ou d'objets), `refresh_interval` et `refresh_behaviour` (`merge`/`replace`), anciens noms `field`/`destination`, `target` facultatif (traduction en place). Comportement de logstash-filter-translate : un `target` déjà présent n'est plus réécrit sans `override => true`, et un champ source absent ne déclenche plus le `fallback`.
- Plugins `filter{}` simples natifs (#120) : `csv`, `cidr`, `prune`, `urldecode`,
  `uuid`, `syslog_pri`, `truncate` (module `simples.py`).
- `dissect` natif (#117) : `convert_datatype` (`int`, `float`) et `tag_on_failure`
  (défaut `_dissectfailure`). Un échec de découpage est désormais tagué, comme
  Logstash, au lieu d'être ignoré en silence.
- Filtre `json { … }` natif dans `--pipeline-conf` (#115) : `source`, `target`,
  `skip_on_invalid_json`, `tag_on_failure`.
- Filtre `fingerprint { … }` natif dans `--pipeline-conf` (#114) : méthodes
  SHA1/SHA256/SHA384/SHA512/MD5, HMAC, MURMUR3, UUID, IPV4_NETWORK,
  `base64encode`, `concatenate_sources`, `concatenate_all_fields`.
- **Plugin `kv` en bloc natif** (#113) : `filter { kv { ... } }` réutilise `filters.KeyValueFilter` — `source` (défaut `message`), `target` (fusion dans un hash existant, comme Logstash), `field_split`, `value_split`, `include_keys`, `exclude_keys`, `prefix`, `trim_key`, `trim_value`, `allow_duplicate_values`. Une clé répétée dans la source vaut la liste de ses valeurs (comportement du plugin officiel) ; `allow_duplicate_values => false` déduplique en gardant l'ordre. Le step `kv` de `--filters` gagne les mêmes options. Ligne `kv` de l'audit #101 mise à jour.
- **Options communes sur tous les filtres** (#116) : `add_field`, `add_tag`, `remove_field`, `remove_tag` s'appliquent après tout filtre natif réussi (`dissect`, `date`, `geoip`, `translate`, `mmdb`, `kv`, `grok`), plus seulement après `mutate`, comme `filter_matched` de Logstash ; jamais après un échec. Fonction partagée `filters.apply_common_options`.
- **`grok {}` natif** dans un pipeline `.conf` (#112) : module `grok.py`, bibliothèque des 70 motifs de base de logstash-patterns-core (Apache-2.0, attribution dans `LICENSES/`), `%{SYNTAXE:champ:int|float}`, groupes nommés `(?<champ>...)`, options `break_on_match`, `overwrite`, `tag_on_failure`, `patterns_dir`, `patterns_files_glob`, `pattern_definitions`, `keep_empty_captures`, `target`. Motifs compilés une fois par jeu d'options.
- **Audit des fonctions Logstash** (#101) : `docs/audit-fonctions-logstash.md`, tableau fonction / fait ou pas fait / commentaires (gabarits sprintf, conditions, plugins `filter{}` et `output{}`, options communes).
- **Authentification par certificat client (mTLS)** (#100) : `--cacert`, `--tls-certificate`, `--tls-key`, mêmes noms que le plugin logstash-output-opensearch, transmis au client opensearch-py. Refus au démarrage si certificat et clé ne vont pas ensemble, si les nœuds sont en `http://` ou si un fichier manque. Test de bout en bout contre un serveur HTTPS local qui exige un certificat client.
- **Métriques Prometheus** (#35) : module `metrics.py` (prometheus-client 0.26.0, registre propre au pont), endpoint `/metrics` activé par `--metrics-port` (désactivé par défaut, écoute sur 127.0.0.1). Compteurs reçus/issues/erreurs, histogrammes de latence d'indexation et de taille, jauges de taille de DLQ et de renvois en attente.
- **Internationalisation** (#38) : journaux `info` et au-dessus et aide de la ligne de commande traduisibles (gettext, domaine `rsyslogstach`, langue choisie par l'environnement), 29 langues listées dans `lang/LINGUAS` (traduction anglaise complète, les autres à faire), `scripts/i18n-update.sh` (mise à jour, `--check`, `--compile`), `scripts/i18n_report.py`, job CI « i18n », workflow `i18n.yml` (PR de mise à jour des catalogues) ; les `.mo` sont installés par la roue dans `share/locale`.
- Règles de protection versionnées `.github/branch-protection/{main,dev}.json` (relevées sur la protection réelle du 22/10/2026), vérifiées par le workflow `branch-protection.yml` (push sur main/dev, chaque jour) et `scripts/check_branch_protection.py` (socle Mathilde-Team/.github#1, #83).
- **`drop {}` natif** dans un pipeline `.conf` (#34) : `if [x] == "bruit" { drop { } }` écarte le document (`apply()` renvoie `None`, comme un step `"drop"` de `filters_json`) ; option `percentage` honorée comme dans Logstash.
- **Step `"date"` dans `--filters`** (#34) : `match`, `target`, `timezone`, `tag_on_failure`, comme le plugin `date` des `.conf`. Les deux mécanismes partagent désormais `filters.DateFilter` (logique déplacée d'`interpreter.py`). Un `match` mal formé est refusé dès le chargement de `--filters` (`ValueError`), et reste ignoré dans un `.conf`.
- **`Makefile`** (#103, fin de #73) : cibles usuelles (`test`, `lint`, `fmt`, `fmt-fix`, `i18n`, `seuil`) exécutant les mêmes commandes que la CI ; le seuil de couverture y est lu depuis `pyproject.toml` (`tomllib`), jamais recopié — une seule source de vérité. Section Tests du README mise à jour.

## [0.9.0] - 2026-10-22

Première version publiée sous forme de release GitHub.

### Ajouté
- **Workflow de release** (#78) : `.github/workflows/release.yml` publie une release GitHub au push d'un tag `vX.Y.Z` sur `main` (tag = version de `pyproject.toml`, notes tirées de la section `## [X.Y.Z]` de ce journal, archive des sources jointe).
