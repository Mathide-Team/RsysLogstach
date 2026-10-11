"""Empreinte déterministe d'un document, pour un document_id OpenSearch idempotent.

Feuille du graphe de dépendances comme `templates`/`enrichment`/`util`/`dlq` :
dépend seulement de `templates` (résolution des chemins de champs imbriqués
via `render_template`, même syntaxe `%{...}`/`%{[a][b]}` que partout
ailleurs dans le projet) et `tracing`. Aucune dépendance dans l'autre sens —
voir `tests/test_no_cross_imports.py::test_templates_has_no_dependency_on_fingerprint`.

Répond à l'item "Proposé" #4 de FEATURES.md (session 17, jusqu'ici
partiellement couvert depuis la session 9 par `--document-id-template`
seul) : un `_id` OpenSearch dérivé d'un HASH du contenu (façon filtre
`fingerprint` de Logstash), pour les documents qui n'ont pas de champ
identifiant naturel — utile surtout en cas de ré-émission par rsyslog après
un accusé de réception perdu (`confirmMessages="on"`, voir `rsyslog.conf`) :
le même document renvoie toujours la même empreinte, donc une ré-indexation
écrase l'original au lieu de le dupliquer, plutôt que de dépendre d'un `_id`
aléatoire (une entrée en double par ré-émission) ou d'un champ pivot que
les logs HPE Comware qui motivent ce projet ne fournissent pas toujours.

Portée volontairement réduite par rapport au filtre `fingerprint` officiel
de Logstash (voir FEATURES.md, "Limites connues") : seuls des algorithmes de
hachage simples et non salés sont couverts (`sha256`/`sha1`/`md5`, module
`hashlib` de la bibliothèque standard) — pas de mode HMAC (nécessiterait une
clé secrète de configuration, hors de portée d'une empreinte de
déduplication plutôt que d'authentification), ni `MURMUR3` (entier 32 bits,
format d'`_id` différent d'un hex digest), ni `IPV4_NETWORK` (portée trop
spécifique à un cas d'usage réseau que rsyslogstach ne rencontre pas ici).
"""

from __future__ import annotations

import hashlib
import json

from templates import render_template
from tracing import traced

_HASH_FACTORIES = {
    "sha256": hashlib.sha256,
    "sha1": hashlib.sha1,
    "md5": hashlib.md5,
}

# Séparateur entre les valeurs de champs concaténées avant hachage — un
# caractère de contrôle improbable dans un log réel (unit separator ASCII),
# pour éviter qu'une simple concaténation ne fasse se confondre deux
# découpages différents des mêmes caractères (ex. champs "ab"/"c" vs
# "a"/"bc" produiraient sinon la même empreinte).
_FIELD_SEPARATOR = "\x1f"


@traced
def compute_fingerprint(doc: dict, fields: list[str] | None, method: str = "sha256") -> str | None:
    """Calcule une empreinte déterministe (hex digest) d'un document.

    Args:
        doc: Document à empreindre.
        fields: Chemins de champs (même syntaxe que l'intérieur d'une
            référence `%{...}`, ex. "host", "[host][ip]") dont les valeurs
            sont concaténées puis hachées, DANS L'ORDRE fourni — l'ordre
            fait partie de l'empreinte : `fields=["a", "b"]` et
            `fields=["b", "a"]` produisent des empreintes différentes pour
            le même document, même sémantique qu'une liste `source` du
            filtre `fingerprint` officiel de Logstash. `None` ou liste
            vide : empreinte du document ENTIER (JSON à clés triées, forme
            canonique — indépendante de l'ordre d'insertion des clés en
            Python), pas d'une sélection de champs.
        method: Algorithme de hachage (`sha256` par défaut, `sha1`, `md5`
            — voir les limites documentées dans la docstring du module).

    Returns:
        Le hex digest (chaîne hexadécimale), ou `None` si TOUS les champs
        demandés sont absents (ou vides) du document — une empreinte sans
        aucune valeur distinctive n'aurait pas de sens, même convention que
        `templates.render` pour un gabarit qui rend une chaîne vide (voir
        `OpenSearchIndexer._document_id`). Un champ présent mais `null`,
        comme pour un gabarit `%{...}` ordinaire, se rend en chaîne vide
        (pas distingué d'un champ absent) — limite héritée de `templates.py`,
        voir FEATURES.md.

    Raises:
        ValueError: `method` non reconnu.
    """
    factory = _HASH_FACTORIES.get(method)
    if factory is None:
        msg = f"méthode de fingerprint inconnue: {method!r} (attendu: {sorted(_HASH_FACTORIES)})"
        raise ValueError(msg)

    if not fields:
        payload = json.dumps(doc, sort_keys=True, default=str, ensure_ascii=False)
    else:
        rendered = [render_template(f"%{{{field}}}", doc, on_missing="empty") for field in fields]
        if not any(rendered):
            return None
        payload = _FIELD_SEPARATOR.join(rendered)

    return factory(payload.encode("utf-8")).hexdigest()
