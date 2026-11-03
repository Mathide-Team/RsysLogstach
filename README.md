# rsyslogstach

**Pont rsyslog → omprog (asyncio) → OpenSearch, compatible schéma/filtres Logstash.**

Pipeline asynchrone en Python qui reçoit les messages syslog via le module `omprog` de rsyslog, applique des filtres et un enrichissement, puis indexe dans OpenSearch — avec Dead Letter Queue pour les échecs permanents et fingerprint déterministe pour l'idempotence.

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

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
| `omprog.py` | Point d'entrée asyncio (rsyslog omprog) | tous les modules métier |
| `tracing.py` | Décorateur `@traced` (loguru) | — |
| `opensearchconf.py` | Connexion OpenSearch lue dans `output { opensearch { … } }` (#125) | tracing |
| `util.py` | `add_failure_tags`, `load_json_file`, `opensearch_auth_from_env` | tracing |
| `templates.py` | `render_template()` — syntaxe `%{field}` / `%{[a][b]}` | tracing |
| `fingerprint.py` | `compute_fingerprint()` et filtre `FingerprintFilter` (#114) | templates, tracing |
| `dlq.py` | `LocalDeadLetterQueue` — JSONL append-only | tracing |
| `enrichment.py` | Enrichissement dictionnaire + GeoIP | tracing |
| `filters.py` | `FilterPipeline` (dissect, drop, regex, kv, mutate, geoip, translate, date) | enrichment, templates, tracing, util |
| `grok.py` | `GrokFilter` — plugin `grok` natif, motifs de base Logstash (#112) | templates, tracing, util |
| `interpreter.py` | `PipelineInterpreter` (`--pipeline-conf` Logstash) | dnslookup, enrichment, filters, fingerprint, grok, i18n, simples, templates, tracing, useragent, util, xmlfilter |
| `useragent.py` | `UserAgentFilter` — plugin `useragent` natif, ua-parser (#121) | templates, tracing |
| `xmlfilter.py` | `XmlFilter` — plugin `xml` natif, lxml (#121) | templates, tracing, util |
| `dnslookup.py` | `DnsFilter` — plugin `dns` natif, dnspython (#121) | templates, tracing, util |
| `simples.py` | plugins `csv`, `cidr`, `prune`, `urldecode`, `uuid`, `syslog_pri`, `truncate` (#120) | i18n, templates, tracing, util |
| `metrics.py` | `Metrics` — compteurs, histogrammes et jauges Prometheus, endpoint `/metrics` | tracing |
| `indexer.py` | `OpenSearchIndexer` (opensearch-py async) | dlq, fingerprint, templates, tracing |

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

Step `date` (#34), mêmes options que le plugin `date` de Logstash : `{"type": "date", "match": ["horodatage", "ISO8601", "MMM dd HH:mm:ss"], "timezone": "Europe/Paris"}` écrit `@timestamp` (ou `target`) en ISO8601 UTC, et ajoute `_dateparsefailure` (ou `tag_on_failure`) aux tags si aucun motif ne correspond. Motifs `SSS` (millisecondes) et `z`/`ZZZ` (fuseau textuel : « CET », « Europe/Paris ») reconnus, ainsi que l'option `locale` (`fr` : noms de mois/jours français, #118). `grok` n'est pas proposé : un step `regex` à groupes nommés le remplace.

### Enrichissement (`enrich-dict.example.json`)

```json
{
  "sw-core-01": {"site": "Besançon - DR", "role": "core", "owner_team": "Infra Réseau"}
}
```

### Pipeline Logstash (`--pipeline-conf`)

Voir `pipeline.example.d/` : input UDP → filter (DNS, GeoIP) → output OpenSearch.

Fonctions Logstash prises en charge (gabarits `%{...}`, conditions, plugins
`filter{}`/`output{}`) et limites : [docs/audit-fonctions-logstash.md](docs/audit-fonctions-logstash.md).

Variables d'environnement du `.conf` (#122) : `${VAR}` et `${VAR:défaut}` sont
substitués au chargement, comme Logstash — la variable définie prime sur la
valeur par défaut ; une variable non définie sans défaut refuse le démarrage
(`ValueError` qui la nomme). `%{champ}` (rendu par événement) n'est pas
concerné.
Sorties `opensearch` (#126) : `action` (`index`, `create`, `update`, `delete`), `pipeline` et `routing` acceptent des gabarits, par exemple `opensearch { index => "logs" action => "update" document_id => "%{id}" doc_as_upsert => true routing => "%{host}" }`.

Nom de champ contenant des crochets (#124) : avec `--field-reference-escape-style percent`, `%{[map%5Bk%5D]}` lit le champ `map[k]` ; `ampersand` utilise `&#91;` et `&#93;`. Défaut `none`, comme Logstash.

Plugins simples natifs (#120) : `csv`, `cidr`, `prune`, `urldecode`, `uuid`, `syslog_pri`, `truncate` ; par exemple `cidr { address => ["%{ip}"] network => ["10.0.0.0/8"] add_tag => ["interne"] }`. `clone` et `split` restent sans effet.

Un `dissect` qui échoue (source absente ou sans correspondance) ajoute `_dissectfailure` aux `tags`, ou les tags de `tag_on_failure` (#117) ; `convert_datatype => { "port" => "int" }` convertit ensuite les champs extraits.
Plugin `kv` natif (#113) : `filter { kv { source => "message" target => "pairs" ... } }`
réutilise le même extracteur que le step `kv` de `--filters` (options
`include_keys`, `exclude_keys`, `trim_key`, `trim_value`,
`allow_duplicate_values` comprises ; clé répétée → liste de valeurs).

Les chaînes entre guillemets sont lues brutes, comme Logstash par défaut
(`config.support_escapes: false`) : `"\d+"` reste `\d+` (#128).

#### `translate` (#119)

```
filter {
  translate {
    source => "[ifTable][index]"
    target => "[ifTable][name]"          # facultatif : traduction en place
    dictionary_path => "/etc/rsyslogstach/ifName.yml"   # ou .json, .csv ; ou dictionary => { "1" => "Uplink" }
    fallback => "index: %{[ifTable][index]}"
    refresh_interval => 300              # relu s'il a changé ; refresh_behaviour => "merge" ou "replace"
  }
}
```

- Comme le plugin officiel : `override` (faux, sauf en place), `exact`,
  `regex` (clés vues comme regex), `exact => false` (remplacement de
  chaque clé trouvée dans la valeur), `iterate_on` (tableau de valeurs ou
  tableau d'objets), anciens noms `field`/`destination`.
- Le même code sert le step `translate` de `--filters`.
- Différences : rechargement au premier document après l'intervalle (pas
  de minuterie) ; clés comparées en texte ; une extension de fichier
  inconnue est lue comme du YAML.

#### `grok` (#112)

```
filter {
  grok {
    match => { "message" => "%{SYSLOGBASE} %{GREEDYDATA:texte}" }
    # ou plusieurs motifs : { "message" => ["%{IP:client} %{NUMBER:octets:int}", "%{GREEDYDATA:brut}"] }
  }
}
```

- Motifs `%{SYNTAXE}`, `%{SYNTAXE:champ}`, `%{SYNTAXE:champ:int|float}`, champs
  imbriqués (`%{IP:[client][ip]}`) et groupes nommés `(?<champ>...)`.
- Bibliothèque de base de Logstash (`USERNAME`, `INT`, `NUMBER`, `WORD`,
  `NOTSPACE`, `DATA`, `GREEDYDATA`, `QUOTEDSTRING`, `UUID`, `MAC`, `IP`,
  `IPV4`, `IPV6`, `HOSTNAME`, `IPORHOST`, `URI`, `PATH`, `TIMESTAMP_ISO8601`,
  `SYSLOGTIMESTAMP`, `SYSLOGBASE`, `HTTPDATE`, `LOGLEVEL`…, 70 motifs).
- Options : `break_on_match` (vrai), `overwrite`, `tag_on_failure`
  (`_grokparsefailure`), `patterns_dir` + `patterns_files_glob`,
  `pattern_definitions`, `keep_empty_captures`, `target`.
- Sans `overwrite`, une capture vers un champ texte existant donne un
  tableau `[ancien, nouveau]`, comme Logstash.
- Différences : moteur `re` de Python (3.11+) au lieu d'Oniguruma — groupes
  nommés, classes POSIX et `\z` sont traduits ; `named_captures_only`
  toujours vrai ; `timeout_millis` non appliqué. Un motif invalide ou
  inconnu est ignoré (journal DEBUG), les autres motifs restent actifs.

#### `useragent` (#121)

```
filter {
  useragent {
    source => "[user_agent][original]"
    # target => "[user_agent]"  (défaut en mode ECS)
  }
}
```

- Analyse par [ua-parser](https://github.com/ua-parser/uap-python) (motifs
  uap-core, comme le parseur Java de Logstash). Champs ECS écrits :
  `[name]`, `[version]` (`89.0.4389.90`), `[device][name]`, `[os][name]`,
  `[os][version]`, `[os][full]` sous la cible ; major, minor et patch dans
  `[@metadata][filter][user_agent][version]` et `[…][os][version]`.
- `ecs_compatibility => disabled` : cible vide (racine) par défaut et anciens
  champs `name`, `device`, `major`, `minor`, `patch`, `version`, `os`,
  `os_name`, `os_full`, `os_version`, `os_major`, `os_minor`, `os_patch`,
  précédés de `prefix`.
- Options : `source` (requis), `target`, `prefix`, `regexes` (fichier
  `regexes.yaml` de uap-core), `lru_cache_size` (100 000). Un tableau donne
  son premier élément ; source absente ou vide : rien. Si `target` égale
  `source`, la source est remplacée.
- Différences : motifs du paquet `ua-parser-builtins` figé dans
  `pyproject.toml`, pas ceux du jar de Logstash ; un User-Agent récent ou
  rare peut être classé autrement. Fichier `regexes` illisible : bloc ignoré
  (journal DEBUG).

#### `xml` (#121)

```
filter {
  xml {
    source => "message"
    target => "doc"
    xpath => { "/evenement/@id" => "[evenement][id]" }
  }
}
```

- `store_xml` (vrai par défaut, `target` requis) : conversion façon
  XmlSimple, comme Logstash — attributs et enfants dans le même objet,
  enfants en tableaux (`force_array`), texte seul en chaîne ou sous
  `content` (`force_content`, ou en présence d'attributs), éléments vides
  omis (`suppress_empty`). L'élément racine n'apparaît pas. Analyse stricte.
- `xpath => { "expression" => "[champ]" }` : analyse tolérante (ou selon
  `parse_options`, par ex. `strict`), résultats en tableau (texte seul avec
  `force_array => false` et un résultat). Préfixes de la racine (défaut sous
  `xmlns`) ou `namespaces` ; `remove_namespaces`.
- Échec d'analyse, expression invalide, tableau de longueur différente de 1
  ou valeur non textuelle : tag `_xmlparsefailure`.
- Sécurité : ni entités externes, ni DTD, ni XInclude, ni réseau ;
  `parse_options` `noent`, `dtdload`, `dtdattr`, `dtdvalid` ou `xinclude`
  rend le bloc invalide (ignoré, journal DEBUG).
- Différences : lxml (libxml2) remplace Nokogiri et REXML ; un document
  sans élément racine, même en mode tolérant, ne donne aucun résultat XPath.

#### `dns` (#121)

```
filter {
  dns {
    reverse => [ "[host][ip]" ]
    action => "replace"
    nameserver => { address => ["192.0.2.53"] search => ["lan"] }
    hit_cache_size => 4096
  }
}
```

- `resolve` (nom → première adresse, IPv4 puis IPv6) et `reverse`
  (adresse → premier nom) ; `action` `append` (défaut, le champ devient
  `[valeur, résultat]`) ou `replace`.
- Résolveurs dans l'ordre : `hostsfile`, `/etc/hosts`, puis `nameserver`
  (chaîne, liste, ou hash `address`/`search`/`ndots`). Sans les deux :
  `/etc/hosts` puis le DNS du système ; avec `hostsfile` seul : aucun DNS.
- `timeout` (0,5 s), `max_retries` (2), `tag_on_timeout` (`_dnstimeout`),
  caches `hit_cache_size`/`hit_cache_ttl` (0, 60 s) et
  `failed_cache_size`/`failed_cache_ttl` (0, 5 s), noms IDNA.
- Comme Logstash, un champ absent est sauté, mais plusieurs valeurs, une
  valeur non textuelle, une adresse invalide ou un échec arrêtent le
  filtre, sans options communes.
- `RSYSLOGSTACH_DNS=off` coupe les requêtes réseau (fichiers hosts
  seulement) ; les tests le positionnent.
- Limite : les nombres écrits `"${VAR}"` ne sont pas encore remplacés
  (#122) : le bloc est alors ignoré (journal DEBUG), c'est le cas de
  `pipeline.example.d/25_…`.

Exemple de filtre `json` natif (#115) : `json { source => "message" target => "payload" skip_on_invalid_json => true }`.

### Index OpenSearch

Template : `opensearch-index-template.json` (index pattern `switch-logs-*`).
Origine et type de chaque champ, exemples de requêtes :
[docs/opensearch-index-schema.md](docs/opensearch-index-schema.md).

## Utilisation

Depuis une installation (issue #31) :

```bash
rsyslogstach \
    --filters /etc/omprog/filters.json \
    --enrich-dict /etc/omprog/enrichment.json \
    --pipeline-conf /etc/omprog/pipeline.d/ \
    --opensearch-host https://localhost:9200 \
    --index-template opensearch-index-template.json \
    --dlq-path /var/log/rsyslogstach/dlq.jsonl
```

Sans installation (extraction seule), l'ancienne forme reste valable :
`PYTHONPATH=src python3 src/omprog.py ...` — mêmes options, même point d'entrée.

### Protocole omprog

Avec `confirmMessages="on"`, `omprog.py` écrit `OK` sur stdout quand il est
prêt, puis une ligne par message :

| Cas | Réponse | Effet côté rsyslog |
|---|---|---|
| Indexé | `OK` | Message confirmé |
| Abandonné par un filtre `drop`, ou aucune branche `output{}` ne correspond | `OK` | Message confirmé, non indexé |
| Échec permanent (400/404) avec `--dlq-path` | `OK` | Message écrit dans la DLQ |
| JSON invalide | `OK` | Écrit dans la DLQ si elle est configurée, sinon seulement journalisé |
| Échec transitoire (nœud injoignable, timeout), ou échec permanent sans DLQ | `Erreur : ...` | Action suspendue, message renvoyé plus tard |

Les journaux vont sur stderr (`--log-level`, `INFO` par défaut) : stdout est
réservé au protocole. Fin de stdin ou SIGTERM : arrêt propre.

Autres options : `--enrich-key-field` / `--enrich-out-field` (`hostname` /
`enrichment` par défaut), `--geoip-db` (avec `--geoip-ip-field`,
`fromhost-ip` par défaut), `--index-pattern` (`switch-logs-%Y.%m.%d`),
`--index-template-name` (`switch-logs`), `--document-id-template`,
`--document-id-fingerprint` (champs séparés par des virgules, ou `*`),
`--filters-on-missing` / `--pipeline-on-missing`, `--no-verify-certs`,
`--cacert` / `--tls-certificate` / `--tls-key` (mTLS, voir plus bas).
`--pipeline-conf` accepte un fichier ou un dossier, dont les `*.conf` sont lus
par ordre de nom comme le fait Logstash. Seules les sorties `opensearch` et
`elasticsearch` d'un pipeline sont honorées (`index`, `document_id`), et
toujours vers les nœuds de `--opensearch-host`.
`PYTHONPATH=src python3 src/omprog.py --help` donne la liste complète.

**Multi-nœuds et failover (#37)** : `--opensearch-host` est répétable ; le transport opensearch-py retente le nœud suivant en cas d'échec de connexion ou de délai (`retry_on_timeout`), et un health check périodique journalise l'état du cluster (`--health-check-interval`, défaut 300 s, 0 = désactivé).

### Métriques Prometheus (issue #35)

Désactivées par défaut. `--metrics-port 9464` démarre un endpoint `/metrics` sur `127.0.0.1` (`--metrics-addr 0.0.0.0` pour l'exposer au réseau) :

| Métrique | Type | Contenu |
|----------|------|---------|
| `rsyslogstach_messages_received_total` | compteur | lignes reçues de rsyslog |
| `rsyslogstach_messages_total{outcome}` | compteur | `indexed`, `dropped` (filtre ou pipeline sans sortie), `dead_lettered`, `retryable` |
| `rsyslogstach_errors_total{cause}` | compteur | `invalid_json`, `not_an_object`, `exception` |
| `rsyslogstach_index_latency_seconds` | histogramme | durée d'un envoi à OpenSearch |
| `rsyslogstach_message_size_bytes` | histogramme | taille des lignes reçues (octets UTF-8) |
| `rsyslogstach_dlq_size_bytes` | jauge | taille du fichier DLQ courant (`--dlq-path`) |
| `rsyslogstach_retry_pending` | jauge | échecs transitoires consécutifs depuis la dernière indexation réussie |

### Rotation de la DLQ (issue #27)

`LocalDeadLetterQueue` sait rotater et purger son fichier JSONL ; tout est
désactivé par défaut (un seul fichier qui grandit, comme avant).

| Paramètre (`dlq.py`) | Option (`omprog.py`) | Effet |
|---|---|---|
| `max_bytes` | `--dlq-max-size 100M` (`parse_size`) | Rotation avant qu'une écriture dépasse cette taille |
| `max_age` | `--dlq-max-age 7d` (`parse_duration`) | Rotation quand la plus ancienne entrée dépasse cet âge |
| `backups` | `--dlq-backups 10` | Fichiers rotatés conservés au maximum |
| `retention` | `--dlq-retention 30d` (`parse_duration`) | Âge maximal d'un fichier rotaté |
| `compress` | `--dlq-no-compress` | Fichiers rotatés en gzip (défaut) |

Fichiers rotatés : `dlq.jsonl.20261010T120000Z.gz` (puis `-1`, `-2`... dans
la même seconde), relisibles avec `zcat`.

### Authentification OpenSearch

```bash
export OPENSEARCH_USER=admin
export OPENSEARCH_PASSWORD=secret
```

#### Dans le `.conf` (issue #125)

Les options de connexion du plugin
[logstash-output-opensearch](https://github.com/opensearch-project/logstash-output-opensearch)
sont lues dans les blocs `opensearch{}` / `elasticsearch{}` de `output{}`,
y compris dans les branches `if` :

```
output {
  opensearch {
    hosts => ["os1:9200", "os2:9200"]
    ssl => true
    ssl_certificate_verification => true
    user => "admin"
    password => "secret"
    cacert => "/etc/rsyslogstach/ca.pem"
    index => "logs-%{+YYYY.MM.dd}"
  }
}
```

| Option | Effet | Équivalent prioritaire |
|---|---|---|
| `hosts` | URL ou liste ; sans schéma : `https` si `ssl => true`, `http` sinon ; port 9200 par défaut | `--opensearch-host` |
| `ssl` | Schéma des URLs sans schéma ; erreur s'il contredit une URL `http://` / `https://` | — |
| `ssl_certificate_verification => false` | Certificats non vérifiés | `--no-verify-certs` |
| `user` / `password` | Authentification basique (les deux ensemble) | `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD` |
| `cacert`, `tls_certificate`, `tls_key` | Fichiers PEM (voir ci-dessous) | `--cacert`, `--tls-certificate`, `--tls-key` |

Le pont n'ouvre qu'une connexion OpenSearch : si deux blocs donnent des
valeurs différentes pour la même option, il refuse de démarrer. Une valeur
`${VAR}` non remplacée est aussi refusée. Un mot de passe en clair dans le
`.conf` est lisible par quiconque lit le fichier : préférer l'environnement.

#### Par certificat client (mTLS, issue #100)

À la place de l'utilisateur et du mot de passe, le pont peut présenter un
certificat client. Les options portent les noms du plugin
[logstash-output-opensearch](https://github.com/opensearch-project/logstash-output-opensearch)
(`lib/logstash/plugin_mixins/opensearch/api_configs.rb`) :

| Logstash (`output { opensearch { … } }`) | rsyslogstach | Rôle |
|---|---|---|
| `cacert => "/etc/…/ca.pem"` | `--cacert /etc/…/ca.pem` | Autorité qui a signé le certificat du cluster |
| `tls_certificate => "/etc/…/client.pem"` | `--tls-certificate /etc/…/client.pem` | Certificat client présenté au cluster |
| `tls_key => "/etc/…/client.key"` | `--tls-key /etc/…/client.key` | Clé privée PEM non chiffrée du certificat |
| `keystore` / `truststore` (JKS, PKCS#12) | non pris en charge | Convertir en PEM (`openssl pkcs12 -in client.p12 -nodes`) |

```bash
src/omprog.py --opensearch-host https://os1:9200 \
    --cacert /etc/rsyslogstach/ca.pem \
    --tls-certificate /etc/rsyslogstach/client.pem \
    --tls-key /etc/rsyslogstach/client.key
```

Certificat et clé vont ensemble, et les nœuds doivent être en `https://` ;
sinon le pont refuse de démarrer. Sans `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD`,
seul le certificat authentifie. Côté OpenSearch (plugin Security), il faut
`plugins.security.ssl.http.clientauth_mode: OPTIONAL` (ou `REQUIRE`) et un
domaine `clientcert_auth_domain` actif dans `config.yml` ; le CN du
certificat devient le nom d'utilisateur, à associer à un rôle dans
`roles_mapping.yml`. La clé doit rester lisible par l'utilisateur de rsyslog
seulement (`chmod 600`).

### Identifiant de document (`_id`)

Deux mécanismes produisent un `_id` déterministe (idempotence : la
ré-émission d'un document l'écrase au lieu de le dupliquer) :

| Mécanisme | Option | Cas d'usage |
|-----------|--------|-------------|
| **Gabarit** | `--document-id-template "%{[event_id]}"` | Le document possède un champ identifiant naturel (n° d'événement, clé unique) — lisible et traçable dans OpenSearch |
| **Fingerprint** | `--document-id-fingerprint "host,seq"` (ou `*` pour le document entier) | Aucun champ identifiant naturel — hash du contenu (`sha256` par défaut, `sha1`/`md5`, ou `murmur3` : entier 32 bits, non cryptographique), comme le filtre `fingerprint` de Logstash |

Les deux peuvent être configurés **simultanément** (issue #33) : le
fingerprint est alors prioritaire — ils ne sont jamais combinés dans un
même `_id`. Ni l'un ni l'autre (défaut), ou rendu vide pour un document :
OpenSearch génère un `_id` aléatoire (comportement historique).

**Mode HMAC** (issue #28) : `--fingerprint-key` (ou la variable
d'environnement `FINGERPRINT_KEY`) fait dépendre l'empreinte d'une clé
secrète — deux déploiements avec des clés différentes produisent des
`_id` incomparables. Combinable avec `sha256`/`sha1`/`md5` (pas avec
`murmur3`).

## Traductions

Les journaux de niveau `info` et au-dessus et l'aide de la ligne de
commande passent par gettext (issue #38, domaine `rsyslogstach`). Le
français est la langue source ; la langue suit l'environnement, comme pour
tout programme gettext (`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`) :

```bash
LANGUAGE=en_US python3 src/omprog.py --help
```

Côté rsyslog, la variable se passe au programme par l'environnement du
service. Les traces `debug`/`trace` restent en français.

| Fichier | Rôle |
|---|---|
| `lang/LINGUAS` | seule liste des 29 langues |
| `lang/messages.pot` | modèle extrait des sources (`xgettext`) |
| `lang/<locale>.po` | une traduction par langue |
| `lang/locale/<locale>/LC_MESSAGES/rsyslogstach.mo` | catalogues compilés, suivis par git et installés par la roue dans `<prefix>/share/locale` |

Catalogues cherchés : `$RSYSLOGSTACH_LOCALEDIR`, puis `lang/locale/` du
dépôt, `<prefix>/share/locale` et `/usr/share/locale`.

**Modifier une chaîne ou en ajouter une** : l'entourer de `_()` (`from
i18n import _`), en gardant les champs `{...}` de loguru, puis lancer
`scripts/i18n-update.sh` (gettext requis : `apt-get install gettext`) et
committer `lang/`. Les traductions existantes sont conservées par
`msgmerge` ; les nouvelles chaînes arrivent avec `msgstr ""`, sans
traduction automatique.

**Traduire** : remplir les `msgstr` de `lang/<locale>.po` en conservant les
champs `{...}` et les `%%`, retirer la marque `fuzzy` après relecture,
puis relancer `scripts/i18n-update.sh` (recompile le `.mo`).

**Ajouter une langue** : ajouter son code à `lang/LINGUAS`, lancer
`scripts/i18n-update.sh` (crée `lang/<code>.po`), traduire, relancer.
Aucun code ni `pyproject.toml` à modifier.

Contrôles :

- `scripts/i18n-update.sh --check` (job « i18n » de la CI) : `.pot` à jour
  avec les sources, `.po` synchronisés, `msgfmt --check`, `.mo` à jour ;
- `scripts/i18n_report.py` : taux de traduction par langue (aussi dans le
  résumé du job) ;
- `tests/test_i18n.py` : chaînes utilisateur marquées, catalogues valides.

Le workflow `i18n.yml` régénère les catalogues après chaque push sur dev
qui change des chaînes et propose une PR (branche
`chore/i18n-catalogues`).

## Tests

```bash
make test        # pytest --cov, seuil bloquant lu dans pyproject.toml
make lint        # ruff check .
make fmt         # ruff format --check .
```

Le `Makefile` exécute les mêmes commandes que la CI ; le seuil de couverture
(95 %) n'est déclaré que dans `pyproject.toml`.

## Licence

RsysLogstach est publié sous **GPL-3.0-or-later**. Le texte officiel de la GPLv3 se trouve dans [`LICENSE`](LICENSE), `pyproject.toml` déclare `license = "GPL-3.0-or-later"`, et chaque fichier de code porte l'en-tête `# SPDX-License-Identifier: GPL-3.0-or-later`.

Le dépôt ne reprend aucun code de Logstash (Apache-2.0) : les filtres sont réimplémentés à partir de la documentation publique. Seule exception, la bibliothèque des motifs `grok` de base (`patterns/legacy/grok-patterns` de [logstash-patterns-core](https://github.com/logstash-plugins/logstash-patterns-core), Copyright 2012-2015 Elasticsearch, Apache-2.0) est recopiée sans modification dans `src/grok.py`, avec attribution ; le texte de la licence Apache-2.0 et la notice d'origine sont dans [`LICENSES/`](LICENSES/) ; cette licence est compatible avec la GPLv3. Les dépendances ne sont pas embarquées, et leurs licences sont compatibles avec la GPLv3 :

| Dépendance | Licence |
|---|---|
| logstash-pipeline-parser 0.0.3 | MIT |
| opensearch-py | Apache-2.0 |
| geoip2, maxminddb | Apache-2.0 |
| prometheus-client | Apache-2.0 AND BSD-2-Clause |
| pyyaml, mmh3, loguru | MIT |
| ua-parser, ua-parser-builtins | Apache-2.0 |
| lxml | BSD-3-Clause |
| dnspython | ISC |

## Suivi

- **Sessions :** Issues #1–#24 (fermées)
- **Fait depuis :** #25 (modules + tests), #26 (ce README), #29 (null vs absent), #30 (intégration), #32 (fichiers de suivi), #37 (failover + health check)
- **Travaux restants :** Issues #28, #31, #33–#35, #38 (liste à jour dans les issues du dépôt et le backlog de FEATURES.md)
- **FEATURES.md :** Statut des fonctionnalités et backlog
- **PATTERNS.md :** Conventions et patterns
- **CLAUDE.md :** Contexte projet et historique
