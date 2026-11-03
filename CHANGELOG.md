# Journal des versions

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Les numéros suivent [SemVer](https://semver.org/lang/fr/), et la version de `pyproject.toml` est égale au tag.

## [Non publié]

- CI et publication : repli GitHub autorisé, publication manuelle sur un tag
  déjà livré dans main, vérification d’ascendance et archives du tag exact.


### Corrigé
- **Gabarits** (#102) : `%{+%s}` rend les secondes depuis l'epoch de `@timestamp`, comme Logstash, au lieu de `%0`.

### Modifié
- **Licence** (#91) : passage de MIT à GPL-3.0-or-later. `LICENSE` contient désormais le texte officiel de la GPLv3 ; s'y ajoutent `license` dans `pyproject.toml`, les en-têtes SPDX, la section Licence du README avec les licences des dépendances, et `tests/test_licence.py`.

### Ajouté
- **Métriques Prometheus** (#35) : module `metrics.py` (prometheus-client 0.26.0, registre propre au pont), endpoint `/metrics` activé par `--metrics-port` (désactivé par défaut, écoute sur 127.0.0.1). Compteurs reçus/issues/erreurs, histogrammes de latence d'indexation et de taille, jauges de taille de DLQ et de renvois en attente.
- **Internationalisation** (#38) : journaux `info` et au-dessus et aide de la ligne de commande traduisibles (gettext, domaine `rsyslogstach`, langue choisie par l'environnement), 29 langues listées dans `lang/LINGUAS` (traduction anglaise complète, les autres à faire), `scripts/i18n-update.sh` (mise à jour, `--check`, `--compile`), `scripts/i18n_report.py`, job CI « i18n », workflow `i18n.yml` (PR de mise à jour des catalogues) ; les `.mo` sont installés par la roue dans `share/locale`.
- Règles de protection versionnées `.github/branch-protection/{main,dev}.json` (relevées sur la protection réelle du 22/10/2026), vérifiées par le workflow `branch-protection.yml` (push sur main/dev, chaque jour) et `scripts/check_branch_protection.py` (socle Mathilde-Team/.github#1, #83).
- **`drop {}` natif** dans un pipeline `.conf` (#34) : `if [x] == "bruit" { drop { } }` écarte le document (`apply()` renvoie `None`, comme un step `"drop"` de `filters_json`) ; option `percentage` honorée comme dans Logstash.
- **Step `"date"` dans `--filters`** (#34) : `match`, `target`, `timezone`, `tag_on_failure`, comme le plugin `date` des `.conf`. Les deux mécanismes partagent désormais `filters.DateFilter` (logique déplacée d'`interpreter.py`). Un `match` mal formé est refusé dès le chargement de `--filters` (`ValueError`), et reste ignoré dans un `.conf`.

## [0.9.0] - 2026-10-22

Première version publiée sous forme de release GitHub.

### Ajouté
- **Workflow de release** (#78) : `.github/workflows/release.yml` publie une release GitHub au push d'un tag `vX.Y.Z` sur `main` (tag = version de `pyproject.toml`, notes tirées de la section `## [X.Y.Z]` de ce journal, archive des sources jointe).
