# Schéma de l'index OpenSearch

Documentation champ par champ de
[`opensearch-index-template.json`](../opensearch-index-template.json)
(issue #36). `tests/test_index_schema_doc.py` échoue si un champ du
template n'est pas décrit ici, ou si un champ décrit ici a disparu du
template.

## Vue d'ensemble

| Élément | Valeur |
|---|---|
| Motif d'index | `switch-logs-*` |
| Priorité du template | 100 |
| Shards / réplicas | 1 / 1 |
| Chaînes non déclarées | `text` + sous-champ `.keyword` (`keyword`, `ignore_above: 256`) via le template dynamique `string_fields` |
| `message` | toujours `text` (template dynamique `message_field`) |

Attention : `pipeline.example.d/30_output_logstash-rsyslog.conf` écrit dans
`rsyslogstach-2.0.1-%{+YYYY.MM.dd}`, qui **ne correspond pas** au motif
`switch-logs-*`. Avec cet exemple tel quel, le template ne s'applique pas
et OpenSearch déduit lui-même les types (par exemple `FromHost` en `text`
au lieu de `ip`). Il faut aligner le nom d'index de sortie et
`index_patterns`.

## Origine des champs

Sources possibles :

- **rsyslog (propriété)** : propriété de message rsyslog, placée dans le
  JSON par le template rsyslog qui alimente omprog. Référence :
  [propriétés rsyslog](https://www.rsyslog.com/doc/configuration/properties.html).
- **rsyslog (option)** : propriété rsyslog passée par une option du
  [property replacer](https://www.rsyslog.com/doc/configuration/property_replacer.html).
- **schéma SystemEvents** : nom de colonne hérité de la table
  `SystemEvents` du schéma MySQL historique de rsyslog
  ([createDB.sql d'ommysql](https://raw.githubusercontent.com/rsyslog/rsyslog/main/plugins/ommysql/createDB.sql)),
  conservé pour la compatibilité des requêtes et tableaux de bord existants.
- **Logstash** : champ de l'événement Logstash, conservé pour la
  compatibilité de schéma avec l'ancienne chaîne rsyslog → Logstash.
- **filtre** / **enrichment** : ajouté par `filters.py` ou `enrichment.py`.

### Champs déclarés

| Champ | Type OpenSearch | Source | Contenu |
|---|---|---|---|
| `@timestamp` | `date` | Logstash | Horodatage de l'événement, champ de temps par défaut des index patterns |
| `@version` | `keyword` | Logstash | Version du format d'événement (`"1"`) |
| `message` | `text` | Logstash / rsyslog | Texte du message (analysé en plein texte, jamais `keyword`) |
| `timestamp` | `date` (`epoch_second`) | rsyslog (propriété) | `timestamp` (= `timereported`, horodatage de l'en-tête syslog), à émettre en secondes Unix (`date-unixtimestamp`) |
| `hostname` | `keyword` | rsyslog (propriété) | Nom d'hôte transmis dans le message syslog |
| `syslogtag` | `keyword` | rsyslog (propriété) | Champ TAG de l'en-tête syslog (ex. `sshd[123]:`) |
| `msg` | `text` | rsyslog (propriété) | Partie MSG du message syslog |
| `msgspifno1stsp` | `text` | rsyslog (option) | `msg` avec `sp-if-no-1st-sp` : un espace seul si le message ne commence pas par une espace, sinon vide (séparateur TAG/MSG de la RFC 3164) |
| `msgdroplastlf` | `text` | rsyslog (option) | `msg` avec `drop-last-lf` : dernier saut de ligne retiré |
| `pri-text` | `keyword` | rsyslog (propriété) | PRI au format `facilité.sévérité<PRI>` (ex. `local7.info<190>`) |
| `program_name` | `keyword` | rsyslog (propriété) | `programname` : nom de programme extrait du TAG (sans PID) |
| `Facility` | `integer` | schéma SystemEvents | Facilité numérique (`syslogfacility`) |
| `syslogfacility-text` | `keyword` | rsyslog (propriété) | Facilité en texte (RFC 5424, table 1) |
| `Priority` | `integer` | schéma SystemEvents | Sévérité numérique (`syslogpriority` = `syslogseverity`) |
| `syslogpriority-text` | `keyword` | rsyslog (propriété) | Sévérité en texte (identique à `syslogseverity-text`) |
| `syslogseverity` | `integer` | rsyslog (propriété) | Sévérité numérique 0-7 |
| `syslogseverity-text` | `keyword` | rsyslog (propriété) | Sévérité en texte (RFC 5424, table 2) |
| `FromHost` | `ip` | schéma SystemEvents | Adresse de l'émetteur : à alimenter avec `fromhost-ip`, le type `ip` refuse un nom d'hôte |
| `protocol-version` | `keyword` | rsyslog (propriété) | VERSION RFC 5424 (vide pour un message RFC 3164) |
| `structured-data` | `text` | rsyslog (propriété) | STRUCTURED-DATA RFC 5424 (`-` si absent) |
| `app-name` | `keyword` | rsyslog (propriété) | APP-NAME RFC 5424 |
| `procid` | `keyword` | rsyslog (propriété) | PROCID RFC 5424 |
| `msgid` | `keyword` | rsyslog (propriété) | MSGID RFC 5424 |
| `inputname` | `keyword` | rsyslog (propriété) | Module d'entrée rsyslog qui a reçu le message (ex. `imudp`) |
| `ReceivedAt` | `date` | schéma SystemEvents | Réception par rsyslog (`timegenerated`) ; formats acceptés : `yyyy-MM-dd HH:mm:ss` (`date-mysql`), RFC 3339, millisecondes Unix |
| `DeviceReportedTime` | `date` | schéma SystemEvents | Horodatage de l'en-tête (`timereported`), mêmes formats |
| `iut` | `keyword` | rsyslog (propriété) | InfoUnitType MonitorWare (rarement renseigné) |
| `pri` | `integer` | rsyslog (propriété) | Valeur PRI brute (facilité × 8 + sévérité) |
| `rawmsg-after-pri` | `text` | rsyslog (propriété) | Message brut reçu, PRI retiré |
| `geoip` | `object` (dynamique) | filtre | Résultat du filtre `geoip` (`filters.py`, GeoIP2/MaxMind) |
| `geoip.ip` | `ip` | filtre | Adresse géolocalisée |
| `geoip.location` | `geo_point` | filtre | Position, pour les cartes et les requêtes `geo_distance` |
| `geoip.latitude` | `half_float` | filtre | Latitude ; `half_float` arrondit à environ 0,03° vers 45°, utiliser `geoip.location` pour la précision |
| `geoip.longitude` | `half_float` | filtre | Longitude, même remarque |
| `enrichment` | `object` (dynamique) | enrichment | Attributs du dictionnaire statique (`enrich-dict.example.json` : `site`, `role`, `owner_team`...) |

### Champs dynamiques

Tout autre champ chaîne (par exemple ceux créés par les filtres `regex` et
`kv` de `filters.example.json` : `module`, `event_name`, `detail`,
`kv_user`...) est indexé en `text` avec un sous-champ `.keyword`. Filtrer
ou agréger sur `champ.keyword` ; au-delà de 256 caractères, la valeur
n'est pas indexée en `keyword` (mais reste dans `_source`). Les champs
numériques convertis par `mutate.convert` (ex. `severity_code`) sont typés
par OpenSearch à leur première apparition.

## Exemples de requêtes

Erreurs et plus graves d'un équipement sur la dernière heure :

```json
GET switch-logs-*/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "hostname": "sw-core-01" } },
        { "range": { "syslogseverity": { "lte": 3 } } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "sort": [{ "@timestamp": "desc" }]
}
```

Recherche plein texte dans le message, limitée à un programme :

```json
GET switch-logs-*/_search
{
  "query": {
    "bool": {
      "must": [{ "match": { "msg": "link down" } }],
      "filter": [{ "term": { "program_name": "IFNET" } }]
    }
  }
}
```

Messages d'un sous-réseau d'émetteurs (`FromHost` est de type `ip`) :

```json
GET switch-logs-*/_search
{
  "query": { "term": { "FromHost": "10.20.0.0/16" } }
}
```

Nombre de messages par site (enrichment) et par sévérité :

```json
GET switch-logs-*/_search
{
  "size": 0,
  "aggs": {
    "par_site": {
      "terms": { "field": "enrichment.site.keyword" },
      "aggs": { "par_severite": { "terms": { "field": "syslogseverity-text" } } }
    }
  }
}
```

Écart entre l'horloge des équipements et la réception (messages reçus plus
de 5 minutes après leur horodatage) :

```json
GET switch-logs-*/_search
{
  "query": {
    "script": {
      "script": "doc['ReceivedAt'].size() > 0 && doc['DeviceReportedTime'].size() > 0 && doc['ReceivedAt'].value.toInstant().toEpochMilli() - doc['DeviceReportedTime'].value.toInstant().toEpochMilli() > 300000"
    }
  }
}
```

Messages géolocalisés à moins de 50 km d'un point :

```json
GET switch-logs-*/_search
{
  "query": {
    "geo_distance": { "distance": "50km", "geoip.location": { "lat": 47.24, "lon": 6.02 } }
  }
}
```
