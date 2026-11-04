# PATTERNS.md — Conventions et patterns

Depuis le découpage #111, les conventions propres à la bibliothèque
(détail du décorateur `@traced`/`@atraced`, exemples de décisions pour garder
le graphe des modules acyclique : `tracing` feuille, `util.add_failure_tags`,
`_build_geoip_record`, `fingerprint → templates`) sont dans le
[PATTERNS.md de PyStashTemplate](https://github.com/Mathilde-Team/PyStashTemplate/blob/main/PATTERNS.md). Restent ici celles
du connecteur, qui depuis la correction du découpage (#171) se réduit à
`omprog.py` et `i18n.py`.

## Traçabilité systématique des fonctions

**Règle :** toute fonction du code applicatif (`src/`, hors `tests/`) est tracée à l'entrée ET à la sortie, par le décorateur `@traced` de `pystashtemplate.tracing`. Uniquement le `__qualname__` dans les logs — jamais les arguments ni la valeur de retour (identifiants OpenSearch, clé HMAC du fingerprint).

## Absence de dépendances circulaires entre modules

**Règle :** le graphe de dépendances entre modules de `src/` reste acyclique, et le connecteur ne réimplémente pas ce que fournit PyStashTemplate.

**Vérification :** `tests/test_no_cross_imports.py` analyse les imports via `ast` (pas de simple relecture) et vérifie mécaniquement l'absence de cycles.

## Secrets en environnement, jamais en argument CLI

**Règle :** Les identifiants OpenSearch sont lus via `os.environ` (`opensearch_auth_from_env`), jamais passés en argument CLI — visibles via `ps aux`.

## Tests sans pytest-asyncio

**Convention :** Les tests async utilisent `asyncio.run()` directement, sans dépendance à `pytest-asyncio` (absente de `requirements-dev.txt`). Voir `test_omprog.py`, `test_integration.py`.

## Package à plat

**Convention :** `src/*.py` sans `__init__.py`, importé via `sys.path` (voir `conftest.py` et `PYTHONPATH=src` dans le déploiement rsyslog). `pyproject.toml` a `package = true` : la roue expose `omprog` et `i18n` au niveau racine (`only-include = ["src"]`).

## Opérations disque hors boucle asyncio

**Convention :** Les écritures disque se font via `asyncio.to_thread` pour ne jamais bloquer la boucle asyncio d'`omprog` (motif introduit session 4, repris par `pystashtemplate.dlq`).
