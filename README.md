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
| `omprog.py` | Point d'entrée asyncio (rsyslog omprog) | tous les modules du connecteur + `pystashtemplate` |
| `i18n.py` | Domaine gettext `rsyslogstach` (chaînes du connecteur) | `pystashtemplate.tracing` |
| `opensearchconf.py` | Connexion OpenSearch lue dans `output { opensearch { … } }` (#125) | `pystashtemplate.tracing` |
| `dlq.py` | `LocalDeadLetterQueue` — JSONL append-only | `pystashtemplate.tracing` |
| `metrics.py` | `Metrics` — compteurs, histogrammes et jauges Prometheus, endpoint `/metrics` | i18n, `pystashtemplate.tracing` |
| `indexer.py` | `OpenSearchIndexer` — délègue à la sortie `OpenSearchOutput` de PyStashTemplate (#160), DLQ et fingerprint locaux | dlq, i18n, `pystashtemplate.fingerprint`, `pystashtemplate.templates`, `pystashtemplate.outputs.opensearch` |

Depuis le découpage #111, la sémantique Logstash partagée vit dans le
dépôt [PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate)
(dépendance figée `v0.2.0`) : `templates` (gabarits `%{field}`), `filters`
(dissect, drop, regex, kv, mutate, geoip, translate, date), `interpreter`
(`PipelineInterpreter`, `--pipeline-conf` Logstash), `enrichment`
(dictionnaire + GeoIP), `grok`, `fingerprint`, `useragent`, `xmlfilter`,
`multievents`, `dnslookup`, `simples`, `util`, `tracing` — chacun gardant
son rôle et ses dépendances croissantes documentés dans ce README jusqu'à
#111. RsysLogstach, lui, reste le connecteur rsyslog : omprog + livraison
(indexer, dlq) + exploitation (metrics), comme tout autre outil (…beat)
pourrait s'appuyer sur PyStashTemplate.

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
  Les options de connexion du bloc sont lues par `opensearchconf.py` (#125,
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

Le dépôt ne reprend aucun code de Logstash (Apache-2.0). Depuis le découpage #111, les filtres et la bibliothèque des motifs `grok` de base (logstash-patterns-core, Apache-2.0, avec sa notice) vivent dans [PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate), dépendance non embarquée. Les dépendances directes et transitives ont des licences compatibles avec la GPLv3 :

| Dépendance | Licence |
|---|---|
| logstash-pipeline-parser 0.0.3 | MIT |
| pystashtemplate (git, tag `v0.2.0`) | GPL-3.0-or-later |
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
- **FEATURES.md :** Statut des fonctionnalités du connecteur et backlog
- **PATTERNS.md :** Conventions du connecteur
- **CLAUDE.md :** Contexte projet et historique
- **Bibliothèque** (filtres, gabarits, `.conf`) : [FEATURES.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/FEATURES.md), [PATTERNS.md](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/PATTERNS.md) et [issues](https://github.com/Mathilde-Team/PyStashTemplate/issues) de PyStashTemplate
