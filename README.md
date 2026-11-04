# rsyslogstach

**Pont rsyslog → omprog (asyncio) → OpenSearch, compatible schéma/filtres Logstash.**

Connecteur asynchrone en Python : il reçoit les messages syslog par le module `omprog` de rsyslog et les confie à [PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate), la bibliothèque qui porte toute la sémantique Logstash (filtres, enrichissement, pipelines `.conf`, indexation OpenSearch, DLQ, `_id` déterministe, métriques). Ce dépôt ne garde que ce qui est propre à rsyslog : le protocole `omprog`, les options de ligne de commande et le câblage.

Pour tout ce qui n'est pas rsyslog (format des filtres, écriture d'un `.conf`, sorties, internationalisation, API Python), la référence est le [README de PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate#readme).

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)

## Architecture

```
rsyslog → omprog (asyncio) → [filters] → [enrichment] → [indexer] → OpenSearch
          └ RsysLogstach ┘   └──────── PyStashTemplate v0.3.0 ────────┘
                                 blocklist      geoip      DLQ (erreurs 4xx)
                                                           fingerprint (_id)
```

### Modules

| Module | Rôle | Dépendances |
|--------|------|-------------|
| `omprog.py` | Point d'entrée asyncio (protocole rsyslog omprog), options de ligne de commande, câblage | `i18n` + `pystashtemplate` |
| `i18n.py` | Domaine gettext `rsyslogstach` (chaînes du connecteur) | `pystashtemplate.tracing` |

Découpage #111 corrigé (#171, v0.11.0) : seul `omprog`, propre à rsyslog,
reste dans ce dépôt. Tout le reste vient de
[PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate)
(dépendance figée `v0.3.0`), utilisable par tout autre outil (service
autonome, …beat) :

- sémantique Logstash : `templates` (gabarits `%{field}`), `filters`
  (dissect, drop, regex, kv, mutate, geoip, translate, date), `interpreter`
  (`PipelineInterpreter`, `--pipeline-conf`), `enrichment` (dictionnaire +
  GeoIP), `grok`, `fingerprint`, `useragent`, `xmlfilter`, `multievents`,
  `dnslookup`, `simples`, `util`, `tracing` ;
- livraison et exploitation : `indexer` (`OpenSearchIndexer`, `_id`,
  `SendOutcome`), `dlq` (DLQ locale, rotation), `metrics` (Prometheus,
  préfixe `rsyslogstach` conservé) et `opensearchconf` (options de
  connexion du `.conf`) — documentés dans
  [docs/indexation-metriques.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md) ;
- sorties agnostiques (`outputs`, plus de vingt destinations) : voir
  [docs/sorties.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/sorties.md).
  `omprog` n'honore aujourd'hui que les blocs `opensearch{}` /
  `elasticsearch{}` d'un `--pipeline-conf`.

Le graphe de dépendances est acyclique, vérifié mécaniquement par `tests/test_no_cross_imports.py` (analyse `ast`).

## Installation

```bash
uv sync                          # environnement isolé (uv.lock)
pip install .                    # installe la commande `rsyslogstach`
pip install -r requirements.txt  # dépendances seules, pour l'extraction sans installation
```

Deux dépendances directes seulement : `loguru` et `pystashtemplate`, figée
sur le tag `v0.3.0` (`pyproject.toml`, `requirements.txt`). Les
dépendances de PyStashTemplate (aiohttp, geoip2, logstash-pipeline-parser,
prometheus-client…) arrivent avec elle. `requirements-dev.txt` ajoute
pytest, pytest-cov, mmdb-writer et ruff.

### Prérequis système

- Python >= 3.11 ;
- rsyslog avec le module `omprog` ;
- un cluster OpenSearch (ou Elasticsearch compatible `_bulk`) ;
- facultatif : base MaxMind GeoIP2 City (`--geoip-db`) ;
- facultatif, pour les traductions : gettext (`apt-get install gettext`).

## Configuration

### rsyslog.conf

```conf
module(load="omprog")
action(type="omprog"
    binary="/usr/local/bin/rsyslogstach --filters /etc/omprog/filters.json --pipeline-conf /etc/omprog/pipeline.d/ --opensearch-host https://localhost:9200 --dlq-path /var/log/rsyslogstach/dlq.jsonl"
    confirmMessages="on"
    template="RSYSLOG_DebugFormat")
```

`confirmMessages="on"` est indispensable : c'est la réponse `OK` / `Erreur`
du connecteur (voir « Protocole omprog ») qui dit à rsyslog de confirmer ou
de renvoyer un message. Les variables d'environnement (`OPENSEARCH_USER`,
`OPENSEARCH_PASSWORD`, `FINGERPRINT_KEY`, `LANGUAGE`…) se passent par
l'environnement du service rsyslog.

### Filtres, enrichissement et pipelines

Le connecteur ne fait que brancher ces formats sur rsyslog ; leur
interprétation est assurée par
[PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate), qui en
porte la documentation depuis le découpage #111 :

| Option d'`omprog.py` | Format | Exemple | Référence |
|---|---|---|---|
| `--filters` | chaîne de filtres JSON (`FilterPipeline`) : drop, regex, kv, mutate, geoip, translate, date, dns | `filters.example.json` (+ `blocklist.example.txt`) | [pipeline-logstash.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/pipeline-logstash.md) |
| `--enrich-dict`, `--enrich-key-field`, `--enrich-out-field` | dictionnaire statique JSON | `enrich-dict.example.json` | [pipeline-logstash.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/pipeline-logstash.md) |
| `--geoip-db`, `--geoip-ip-field`, `--geoip-out-field` | base MaxMind GeoIP2 City (`.mmdb`) | — | [FEATURES.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/FEATURES.md) |
| `--pipeline-conf` | pipeline Logstash `.conf` (`filter{}`, `output{}`, conditions, gabarits `%{…}`) | `pipeline.example.d/` : input UDP → filter (DNS, GeoIP) → output OpenSearch | [pipeline-logstash.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/pipeline-logstash.md), [audit des fonctions](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/audit-fonctions-logstash.md) |

```json
[
  {"type": "drop", "source": "msg", "words_file": "/etc/omprog/blocklist.txt", "mode": "contains"},
  {"type": "kv", "source": "detail", "field_split": " ", "value_split": "=", "prefix": "kv_"}
]
```

Ce qui relève du connecteur dans un `.conf` :

- **Sorties** : `output { opensearch { … } }` et `elasticsearch { … }`
  sont honorées (`index`, `document_id`) ; `action` (`index`, `create`,
  `update`, `delete`), `pipeline` et `routing` acceptent des gabarits (#126),
  par exemple `opensearch { index => "logs" action => "update" document_id => "%{id}" doc_as_upsert => true routing => "%{host}" }`.
  Les options de connexion du bloc sont lues par `pystashtemplate.opensearchconf` (#125,
  section « Authentification OpenSearch »).
- **Plusieurs événements par message** (`clone`, `split`, #141) : chacun est
  indexé selon ses propres sorties ; rsyslog reçoit un échec transitoire si
  l'indexation de l'un d'eux échoue, et renvoie alors le message entier.
- **Variables `${VAR}`** (#122) : substituées au chargement ; une variable
  non définie sans défaut refuse le démarrage d'`omprog.py`.
- **`--field-reference-escape-style`** (#124) : `none` (défaut, comme
  Logstash), `percent` ou `ampersand`, transmis aux gabarits.
- **`PYSTASHTEMPLATE_DNS=off`** (ancien nom `RSYSLOGSTACH_DNS` toujours lu)
  coupe les requêtes DNS réseau du filtre `dns`.

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

**Multi-nœuds et failover (#37, revu par #160)** : `--opensearch-host` est répétable, mais la sortie `OpenSearchOutput` de PyStashTemplate (API `_bulk`) n'utilise que le PREMIER nœud — le failover revient à l'appelant : un échec rend le message à rsyslog (`RETRYABLE`), qui le retient et le renvoie. Un health check périodique journalise l'état du cluster (`--health-check-interval`, défaut 300 s, 0 = désactivé).

### Métriques Prometheus (issue #35)

Fournies par `pystashtemplate.metrics` ([référence](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md#métriques-prometheus-metrics)) ;
le connecteur les crée avec le préfixe `rsyslogstach` (`METRICS_PREFIX`), les noms restent donc ceux d'avant le découpage. Désactivées par défaut. `--metrics-port 9464` démarre un endpoint `/metrics` sur `127.0.0.1` (`--metrics-addr 0.0.0.0` pour l'exposer au réseau) :

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

Les messages en échec permanent sont écrits par `pystashtemplate.dlq.LocalDeadLetterQueue`
([référence](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md#dlq-locale-dlq)),
activée par `--dlq-path`. Rotation et purge sont désactivées par défaut :

| Option | Exemple | Effet |
|---|---|---|
| `--dlq-max-size` | `100M` | Rotation avant qu'une écriture dépasse cette taille |
| `--dlq-max-age` | `7d` | Rotation quand la plus ancienne entrée dépasse cet âge |
| `--dlq-backups` | `10` | Fichiers rotatés conservés au maximum |
| `--dlq-retention` | `30d` | Âge maximal d'un fichier rotaté |
| `--dlq-no-compress` | — | Fichiers rotatés non compressés (gzip par défaut) |

Fichiers rotatés : `dlq.jsonl.20261010T120000Z.gz`, relisibles avec `zcat`.

### Authentification OpenSearch

```bash
export OPENSEARCH_USER=admin
export OPENSEARCH_PASSWORD=secret
```

#### Dans le `.conf` (issue #125)

Lecture assurée par `pystashtemplate.opensearchconf`
([référence](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md#options-de-connexion-du-conf-opensearchconf)). Les options de connexion du plugin
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

Calculé par `pystashtemplate.indexer`, dont la [référence](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/docs/indexation-metriques.md#identifiant-de-document-_id)
détaille les algorithmes. Côté connecteur :

| Option | Effet |
|---|---|
| `--document-id-template "%{[event_id]}"` | `_id` tiré d'un champ identifiant naturel |
| `--document-id-fingerprint "host,seq"` (ou `*`) | `_id` = empreinte du contenu (`sha256` par défaut, `sha1`, `md5`, `murmur3`), prioritaire sur le gabarit |
| `--fingerprint-key` / `FINGERPRINT_KEY` | Mode HMAC : empreinte dépendant d'une clé secrète (pas avec `murmur3`) |

Sans aucune de ces options, ou si le `_id` calculé est vide, OpenSearch
génère un `_id` aléatoire. Un `_id` déterministe rend la ré-émission par
rsyslog idempotente : le document est écrasé, pas dupliqué.

## Traductions

Les journaux de niveau `info` et au-dessus et l'aide de la ligne de
commande passent par gettext, domaine `rsyslogstach` (issue #38) ; les
messages venus de la bibliothèque utilisent le domaine `pystashtemplate`.
Le français est la langue source ; la langue suit l'environnement
(`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`) :

```bash
LANGUAGE=en_US rsyslogstach --help
```

Catalogues cherchés : `$RSYSLOGSTACH_LOCALEDIR`, puis `lang/locale/` du
dépôt, `<prefix>/share/locale` et `/usr/share/locale`. Les fichiers
(`lang/LINGUAS`, `lang/messages.pot`, `lang/<locale>.po`, `.mo` compilés)
et la marche à suivre pour modifier une chaîne, traduire ou ajouter une
langue sont les mêmes que dans PyStashTemplate : voir la section
« Internationalisation » de son [README](https://github.com/Mathilde-Team/PyStashTemplate#readme). Ici, on marque les
chaînes avec `from i18n import _`, puis `scripts/i18n-update.sh` ;
`scripts/i18n-update.sh --check` est le job « i18n » de la CI.

## Tests

```bash
make test        # pytest --cov, seuil bloquant lu dans pyproject.toml
make lint        # ruff check .
make fmt         # ruff format --check .
```

Le `Makefile` exécute les mêmes commandes que la CI ; le seuil de couverture
(95 %) n'est déclaré que dans `pyproject.toml`. La CI lance aussi
`scripts/i18n-update.sh --check` ; `tests/test_loguru_regles.py` exécute
`scripts/audit_debug_sorties.py` (traces `debug` à l'entrée et à la sortie
des fonctions). Les tests des
filtres, du `.conf`, de l'indexation et de la DLQ vivent dans
PyStashTemplate ; ceux d'ici couvrent le protocole `omprog`, les options et
le câblage, `tests/test_no_cross_imports.py` vérifiant que le connecteur
ne dépend que de lui-même et du paquet `pystashtemplate`, sans copie de ses modules.

## Licence

RsysLogstach est publié sous **GPL-3.0-or-later**. Le texte officiel de la GPLv3 se trouve dans [`LICENSE`](LICENSE), `pyproject.toml` déclare `license = "GPL-3.0-or-later"`, et chaque fichier de code porte l'en-tête `# SPDX-License-Identifier: GPL-3.0-or-later`.

Le dépôt ne reprend aucun code de Logstash (Apache-2.0). Les filtres et les motifs `grok` de base (logstash-patterns-core, Apache-2.0, avec sa notice) vivent dans PyStashTemplate, dépendance non embarquée. Dépendances directes :

| Dépendance | Licence |
|---|---|
| pystashtemplate (git, tag `v0.3.0`) | GPL-3.0-or-later |
| loguru | MIT |

Les licences des dépendances de PyStashTemplate, toutes compatibles avec la GPLv3, sont listées dans la section « Licence » de son [README](https://github.com/Mathilde-Team/PyStashTemplate#licence).

## Suivi

- Version et historique : [CHANGELOG.md](CHANGELOG.md), [releases](https://github.com/Mathilde-Team/RsysLogstach/releases).
- Travaux du connecteur : [issues de RsysLogstach](https://github.com/Mathilde-Team/RsysLogstach/issues) ; statut et backlog dans [FEATURES.md](FEATURES.md), conventions dans [PATTERNS.md](PATTERNS.md).
- Tout ce qui relève de la sémantique Logstash, des sorties, de l'indexation, de la DLQ et des métriques se suit dans les [issues de PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate/issues) ; les issues correspondantes de ce dépôt y ont été transférées lors du découpage (#111, #171).
- Mise à jour de la bibliothèque : changer le tag dans `pyproject.toml` et `requirements.txt`, puis `uv lock`.
