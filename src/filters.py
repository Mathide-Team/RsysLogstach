"""Filtres d'extraction façon Logstash filter{} (dissect, regex, kv, drop, mutate, geoip, translate).

Extrait d'omprog.py (session 9, réorganisation selon le squelette de
Mathilde) pour respecter la séparation en modules à responsabilité unique
du squelette — voir PATTERNS.md, "Absence de dépendances circulaires
entre modules". Dépend de `tracing` et, depuis la session 14, de
`templates` (pour le rendu des gabarits sprintf de `mutate.add_field`,
voir `apply_mutate`/`MutateFilter` plus bas) ; jamais de `indexer`.

Depuis la session 24, dépend aussi de `enrichment` (`GeoIPLookup`, pour le
step "geoip", voir `GeoipFilter` plus bas) et de `util`
(`add_failure_tags`, partagée avec `interpreter.py::PipelineInterpreter`
pour le `tag_on_failure` de `date`/`geoip`) — les deux restent des feuilles
du graphe de dépendances (ne dépendent que de `tracing`), aucun risque de
cycle : voir PATTERNS.md pour le détail de cette nouvelle arête.

Depuis la session 25, `enrichment` sert aussi à `TranslateDictionary` (step
"translate", voir `TranslateFilter` plus bas) — aucune arête supplémentaire
dans le graphe de dépendances, `filters -> enrichment` existe déjà depuis
la session 24 pour `GeoIPLookup`.

Voir filters.example.json pour un exemple bâti sur le format de message
typique des switches HPE Comware ("%%10MODULE/sévérité/ÉVÉNEMENT: détail"),
et blocklist.example.txt pour le format attendu par `load_word_list`.
"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import maxminddb
import yaml
from loguru import logger

from enrichment import GeoIPLookup, TranslateDictionary
from templates import _MISSING, assign_field, parse_field_path, remove_field_path, render_template, resolve_field
from tracing import traced
from util import add_failure_tags


@dataclass
class _Field:
    """Un champ extrait par un patron dissect, avec ses modificateurs."""

    name: str
    append: bool = False
    skip: bool = False
    skip_repeated_delimiter: bool = False


class Dissector:
    """Extraction de champs à partir d'un patron positionnel (façon filtre dissect de Logstash).

    Contrairement à un grok (regex), un patron dissect découpe une chaîne sur
    des délimiteurs littéraux entre marqueurs %{champ} : plus rapide qu'une
    regex, mais suppose une structure de délimiteurs fixe. Modificateurs pris
    en charge : %{+champ} (concatène à un champ du même nom déjà extrait),
    %{?champ} ou %{} (extrait sans conserver dans le résultat), %{champ->}
    (ignore les répétitions du délimiteur qui suit, utile pour des espaces
    multiples). %{&champ} (référence indirecte, une fonctionnalité plus rare
    du dissect Logstash) n'est pas pris en charge.
    """

    @traced
    def __init__(self, pattern: str) -> None:
        """Compile un patron dissect.

        Args:
            pattern: Patron du type "%{a}/%{b}: %{c}".

        Raises:
            ValueError: Patron sans aucun champ %{...}.
        """
        matches = list(re.finditer(r"%\{([^}]*)\}", pattern))
        if not matches:
            raise ValueError(f"patron dissect sans aucun champ %{{...}}: {pattern!r}")
        self._leading = pattern[: matches[0].start()]
        self._fields = [self._parse_token(match.group(1)) for match in matches]
        self._delims = [pattern[matches[i].end() : matches[i + 1].start()] for i in range(len(matches) - 1)]
        self._trailing = pattern[matches[-1].end() :]

    @staticmethod
    @traced
    def _parse_token(token: str) -> _Field:
        """Interprète un token %{...} et ses modificateurs."""
        skip_repeated_delimiter = token.endswith("->")
        if skip_repeated_delimiter:
            token = token[: -len("->")]
        append = token.startswith("+")
        skip = token.startswith("?") or token == ""
        name = token.lstrip("+?")
        return _Field(name, append=append, skip=skip, skip_repeated_delimiter=skip_repeated_delimiter)

    @traced
    def apply(self, source: str) -> dict[str, str] | None:
        """Applique le patron à une chaîne source.

        Args:
            source: Chaîne à découper.

        Returns:
            Le dictionnaire des champs extraits, ou None si un délimiteur du
            patron est introuvable dans la source (structure inattendue).
        """
        if not source.startswith(self._leading):
            return None
        pos = len(self._leading)
        result: dict[str, str] = {}
        for index, field in enumerate(self._fields):
            is_last = index == len(self._fields) - 1
            delim = self._trailing if is_last else self._delims[index]
            if delim:
                delim_pos = source.find(delim, pos)
                if delim_pos == -1:
                    return None
                value = source[pos:delim_pos]
                pos = delim_pos + len(delim)
                if field.skip_repeated_delimiter:
                    while source.startswith(delim, pos):
                        pos += len(delim)
            else:
                value = source[pos:]
                pos = len(source)
            if not field.skip:
                if field.append and field.name in result:
                    result[field.name] = result[field.name] + value
                else:
                    result[field.name] = value
        return result


class RegexFilter:
    """Extraction de champs par expression régulière à groupes nommés (grok simplifié).

    Complète Dissector pour les structures qu'un patron positionnel ne peut
    pas exprimer, typiquement un préfixe collé sans délimiteur (ex. le "10"
    et "IFNET" de "%%10IFNET/3/LINK_UPDOWN" chez les switches HPE Comware).
    """

    @traced
    def __init__(self, pattern: str) -> None:
        """Compile l'expression régulière.

        Args:
            pattern: Regex Python à groupes nommés, ex.
                r"%%\\d+(?P<module>[A-Z_]+)/(?P<severity_code>\\d+)/(?P<event_name>[A-Z_]+): ?(?P<detail>.*)".
        """
        self._regex = re.compile(pattern)

    @traced
    def apply(self, source: str) -> dict[str, str] | None:
        """Applique la regex à `source`.

        Args:
            source: Chaîne à analyser.

        Returns:
            Les groupes nommés capturés, ou None si la regex ne correspond pas.
        """
        match = self._regex.match(source)
        if match is None:
            return None
        return match.groupdict()


class KeyValueFilter:
    """Extraction de paires clé/valeur (façon filtre kv de Logstash)."""

    @traced
    def __init__(self, field_split: str = " ", value_split: str = "=", prefix: str = "") -> None:
        """Initialise l'extracteur.

        Args:
            field_split: Séparateur entre paires (espace par défaut).
            value_split: Séparateur entre clé et valeur ("=" par défaut).
            prefix: Préfixe ajouté à chaque nom de champ extrait, pour
                éviter les collisions avec des champs existants.
        """
        self._field_split = field_split
        self._value_split = value_split
        self._prefix = prefix

    @traced
    def apply(self, source: str) -> dict[str, str]:
        """Découpe `source` en paires clé/valeur.

        Args:
            source: Chaîne à analyser, ex. "user=admin action=login result=ok".

        Returns:
            Les paires trouvées (clés préfixées par `prefix`) ; les segments
            sans séparateur value_split sont ignorés.
        """
        result: dict[str, str] = {}
        for token in source.split(self._field_split):
            if self._value_split not in token:
                continue
            key, _, value = token.partition(self._value_split)
            key = key.strip()
            if key:
                result[self._prefix + key] = value.strip()
        return result


class DropFilter:
    """Bloque (drop) le document si la valeur testée correspond à un mot d'une liste.

    Équivalent d'un filtre drop{} conditionnel de Logstash : liste de mots
    chargée depuis un fichier texte (load_word_list) ou fournie en ligne.
    Comparaison insensible à la casse par défaut.
    """

    @traced
    def __init__(self, words: list[str], mode: str = "contains", case_sensitive: bool = False) -> None:
        """Compile la liste de blocage.

        Args:
            words: Motifs à comparer.
            mode: "equals" (égalité stricte du champ entier) ou "contains"
                (le champ contient un des motifs comme sous-chaîne).
            case_sensitive: Comparaison sensible à la casse si True.

        Raises:
            ValueError: mode inconnu.
        """
        if mode not in ("equals", "contains"):
            raise ValueError(f"mode de drop inconnu: {mode!r} (attendu 'equals' ou 'contains')")
        self._mode = mode
        self._case_sensitive = case_sensitive
        self._words = words if case_sensitive else [word.lower() for word in words]

    @traced
    def matches(self, value: str) -> bool:
        """Indique si `value` correspond à un des mots de la liste (donc si le document doit être bloqué).

        Args:
            value: Valeur du champ testé.

        Returns:
            True si le document doit être bloqué.
        """
        haystack = value if self._case_sensitive else value.lower()
        if self._mode == "equals":
            return haystack in self._words
        return any(word in haystack for word in self._words)


MUTATE_HANDLED_KEYS = (
    "coerce",
    "rename",
    "update",
    "replace",
    "convert",
    "gsub",
    "uppercase",
    "capitalize",
    "lowercase",
    "strip",
    "split",
    "join",
    "merge",
    "copy",
    "add_field",
    "add_tag",
    "remove_field",
    "remove_tag",
    "tag_on_failure",
)


@traced
def convert_value(value: Any, target_type: str, field_name: str) -> Any:
    """Caste `value` selon `target_type` (`mutate.convert`), façon Logstash.

    Une conversion impossible (ex. `int("abc")`) laisse `value` inchangée
    (log en DEBUG) plutôt que de faire échouer tout le document — même
    philosophie que `FilterPipeline.apply` pour un filtre sans
    correspondance.
    """
    try:
        if target_type in ("integer", "integer_eu", "int"):
            return int(str(value).replace(",", "").strip())
        if target_type in ("float", "float_eu"):
            return float(str(value).replace(",", "."))
        if target_type in ("string", "str"):
            return str(value)
        if target_type in ("boolean", "bool"):
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ("true", "t", "yes", "y", "1")
    except (TypeError, ValueError):
        logger.debug("conversion mutate impossible, champ inchangé : {}={!r} -> {}", field_name, value, target_type)
        return value
    logger.debug("type de conversion mutate inconnu, champ inchangé : {}", target_type)
    return value


@traced
def apply_gsub(doc: dict[str, Any], gsub: list) -> None:
    """`mutate { gsub => ["champ", "motif_regex", "remplacement", "champ2", ...] }` (triplets).

    "champ" accepte un chemin imbriqué façon `%{...}` (ex.
    `"[host][domain]"`) depuis la session 15, comme les autres options
    `mutate` — voir `apply_mutate`.
    """
    for i in range(0, len(gsub) - 2, 3):
        field_ref, pattern, replacement = gsub[i], gsub[i + 1], gsub[i + 2]
        path = parse_field_path(field_ref)
        value = resolve_field(doc, path)
        if isinstance(value, str) and isinstance(pattern, str):
            try:
                assign_field(doc, path, re.sub(pattern, replacement, value))
            except re.error:
                logger.debug("motif gsub invalide, ignoré : champ={} motif={!r}", field_ref, pattern)


def _assign_mutate_field(
    doc: dict[str, Any], key: str, raw_value: Any, *, now: datetime | None, on_missing: str
) -> None:
    """Rend (si besoin) puis écrit une valeur à son chemin de champ.

    Partagée par `add_field`/`replace` (session 15) et, depuis la
    session 20, par `update`/`coerce` : les quatre options écrivent une
    valeur (littérale ou gabarit sprintf) à un chemin de champ de la même
    façon, seule la CONDITION préalable diffère (voir `apply_mutate` —
    `add_field`/`replace` inconditionnels, `update` seulement si le champ
    existe déjà, `coerce` seulement si le champ existe et vaut `null`).
    `add_field`/`replace` ont le même effet dans cette implémentation
    volontairement simplifiée (voir "Limites assumées" dans la docstring
    du module `filters.py` concerné — pas de logique d'ajout à un tableau
    existant façon Logstash pour `add_field` sur un champ déjà présent).
    """
    rendered = (
        render_template(raw_value, doc, now=now, on_missing=on_missing) if isinstance(raw_value, str) else raw_value
    )
    assign_field(doc, parse_field_path(key), rendered)


def _apply_string_case(doc: dict[str, Any], field_ref: str, transform: Any) -> None:
    """Applique `transform` (`str.upper`/`str.lower`/`str.capitalize`) à un champ texte, en place.

    Partagée par `uppercase`/`capitalize`/`lowercase` (session 20) : les
    trois options n'ont que la fonction de transformation qui change,
    tout le reste (résolution du chemin, tolérance à un champ absent/non
    textuel) est identique. Champ absent ou non textuel : ignoré
    silencieusement, même tolérance que `strip` (qui ne s'applique lui
    aussi qu'à une valeur `str`) — cohérent avec le comportement officiel
    documenté ("Only works on string fields" pour `split`, même principe
    retenu ici bien que non explicitement écrit pour ces trois options).
    """
    path = parse_field_path(field_ref)
    value = resolve_field(doc, path)
    if isinstance(value, str):
        assign_field(doc, path, transform(value))


def _apply_merge(doc: dict[str, Any], dest_ref: str, source_ref: str) -> None:
    """`mutate.merge` (session 20) : fusionne `source_ref` DANS `dest_ref`, en place.

    Reproduit la matrice documentée par Logstash lui-même : deux hash
    fusionnent (`dict.update`, la source l'emporte sur des clés
    communes) ; une chaîne se comporte comme une liste à un seul élément
    pour la fusion (conversion automatique — `array + string` fonctionne,
    `string + string` produit un tableau à deux éléments dans
    `dest_field`) ; `array`/`string` et `hash` ne se combinent JAMAIS
    ("array et hash ne fonctionnent pas ensemble", doc officielle) —
    journalisé en DEBUG et ignoré plutôt que de deviner une fusion
    arbitraire. Un `dest_ref` absent reçoit directement la valeur de
    `source_ref` telle quelle (cas non documenté explicitement par
    Logstash mais sans ambiguïté : rien à fusionner encore).
    """
    dest_path = parse_field_path(dest_ref)
    source_path = parse_field_path(source_ref)
    dest_value = resolve_field(doc, dest_path)
    source_value = resolve_field(doc, source_path)
    if source_value is _MISSING:
        return
    if dest_value is _MISSING:
        assign_field(doc, dest_path, source_value)
        return
    if isinstance(dest_value, dict) and isinstance(source_value, dict):
        merged = dict(dest_value)
        merged.update(source_value)
        assign_field(doc, dest_path, merged)
    elif isinstance(dest_value, dict) or isinstance(source_value, dict):
        logger.debug(
            "merge impossible (hash incompatible avec un tableau/une chaîne), ignoré : {} <- {}",
            dest_ref,
            source_ref,
        )
    else:
        dest_list = dest_value if isinstance(dest_value, list) else [dest_value]
        source_list = source_value if isinstance(source_value, list) else [source_value]
        assign_field(doc, dest_path, dest_list + source_list)


@traced
def apply_mutate(
    doc: dict[str, Any], options: dict[str, Any], *, now: datetime | None = None, on_missing: str = "keep"
) -> None:
    """Applique un ensemble d'options `mutate` façon Logstash à `doc`, en place.

    Fonction pure, unique implémentation partagée par `MutateFilter`
    (ce module, étape "mutate" de `FilterPipeline`/`--filters`, session 14)
    ET `interpreter.PipelineInterpreter._apply_mutate` (`filter { mutate
    { ... } }` d'un pipeline `.conf`, session 11) — un seul endroit qui
    connaît la sémantique de chaque option, aucune duplication entre les
    deux mécanismes de filtrage du projet (voir PATTERNS.md).

    Chemins de champs imbriqués (session 15) : chaque nom de champ
    manipulé ici (hors `add_tag`/`remove_tag`, toujours plats) accepte la
    même syntaxe qu'une référence `%{...}` — `"hostname"` (plat) ou
    `"[syslog][name]"` (imbriqué), via `templates.parse_field_path`/
    `assign_field`/`resolve_field`/`remove_field_path`. Avant la
    session 15, ces options ne traitaient chaque clé QUE comme une clé
    plate littérale : un `add_field => { "[syslog][name]" => ... }`
    écrivait une clé au nom `"[syslog][name]"` au premier niveau du
    document, au lieu de `doc["syslog"]["name"]` — confirmé en rejouant un
    pipeline de production réel (voir CLAUDE.md, session 15).

    Ordre d'application (session 20) : reproduit l'ordre RÉEL documenté
    par le plugin `mutate` officiel de Logstash ("Mutations in a config
    file are executed in this order") — `coerce`, `rename`, `update`,
    `replace`, `convert`, `gsub`, `uppercase`, `capitalize`, `lowercase`,
    `strip`, `split`, `join`, `merge`, `copy` — puis les quatre options
    COMMUNES à TOUT filtre Logstash (`add_field`, `add_tag`,
    `remove_field`, `remove_tag`, dans cet ordre précis — reproduit
    `LogStash::Filters::Base#filter_matched`, pas la liste "mutate"
    ci-dessus, dont elles sont d'ailleurs absentes), toujours après les
    mutations propres à `mutate` elle-même. Avant cette session, l'ordre
    utilisé ici était arbitraire (`rename`/`convert`/`gsub`/`strip`/
    `add_field`/`replace`/`remove_field`/`add_tag`/`remove_tag`) — un
    écart de comportement réel si un même champ est touché par deux
    options d'un seul bloc (ex. `convert` puis `strip` ne rend pas le
    même résultat que l'inverse sur une valeur avec des espaces
    superflus), resté sans conséquence observable jusqu'ici car aucun
    test/pipeline réel de ce projet ne combinait deux options sur un même
    champ dans un seul bloc `mutate` (vérifié en relisant chaque
    combinaison existante avant ce changement, voir CLAUDE.md session 20).

    `tag_on_failure` (session 23, chaîne unique, défaut `"_mutate_error"`
    — DIFFÉRENT de `tag_on_failure` de `grok`/`date`/`geoip`, validé par
    Logstash comme une LISTE de tags, jamais une chaîne unique ; vérifié
    via le code source réel du plugin officiel, pas supposé par analogie
    avec les autres) : TOUTE la séquence ci-dessus (mutations propres à
    `mutate` PUIS options communes) est protégée par un seul bloc
    try/except, reproduisant `filter(event) ... rescue => ex ...
    event.tag(@tag_on_failure)` du plugin RÉEL — si une opération lève une
    exception, les opérations déjà exécutées avant elle restent
    appliquées (aucun rollback, comme Logstash), celles qui suivaient dans
    l'ordre ci-dessus, `add_field`/`add_tag`/`remove_field`/`remove_tag`
    INCLUS, sont purement et simplement SAUTÉES (jamais exécutées), et le
    tag est ajouté à `doc["tags"]` (sans doublon) à la place. Une valeur
    de `tag_on_failure` qui n'est pas une chaîne (ex. une liste, par
    analogie erronée avec `grok`/`date`/`geoip`) retombe sur le défaut
    `"_mutate_error"` plutôt que d'être silencieusement ignorée — cohérent
    avec la validation stricte `:validate => :string` du plugin officiel
    (une configuration qui s'attend à ce comportement de LISTE échouerait
    au démarrage sur un vrai Logstash ; ce projet, plus tolérant, retombe
    sur le défaut au lieu de faire échouer tout le chargement du
    pipeline).

    Concrètement, deux cas RÉELS (pas seulement théoriques) lèvent
    aujourd'hui une exception dans ce module, jusqu'ici NON interceptée :
    `split => { champ => "" }` (séparateur vide, `str.split("")` lève
    `ValueError` en Python — cas qui, avant cette session, faisait
    planter tout le traitement du document plutôt que d'être toléré comme
    les autres erreurs déjà gérées individuellement, ex. `merge`
    hash/tableau incompatible) et un chemin de champ imbriqué mal formé
    dans N'IMPORTE laquelle des options ci-dessus (ex.
    `rename => { "[host" => "renamed" }`, crochet non refermé —
    `templates.parse_field_path` lève déjà `ValueError` pour ce cas,
    documenté depuis la session 15, mais jamais intercepté par
    `apply_mutate` lui-même avant cette session).

    Args:
        doc: Document à modifier en place.
        options: Options `mutate` au format JSON — dict {champ: valeur}
            pour `coerce`/`rename`/`update`/`replace`/`convert`/`split`/
            `join`/`merge`/`copy` ; `gsub` en liste plate de triplets
            [champ, motif, remplacement, champ2, ...] ; listes de noms de
            champs/tags pour `uppercase`/`capitalize`/`lowercase`/
            `strip`/`remove_field`/`add_tag`/`remove_tag` — mêmes formes
            que la syntaxe `mutate` officielle de Logstash (hash => dict
            JSON, array => liste JSON), qu'il s'agisse d'un step JSON
            `--filters` ou d'un bloc `.conf` déjà normalisé par
            `interpreter._normalize_attrs`. `add_tag`/`remove_tag`
            restent des noms de tags plats (jamais des chemins imbriqués),
            comme dans Logstash. `tag_on_failure` : chaîne unique, voir
            plus haut.
        now: Horodatage pour le rendu des gabarits sprintf de `add_field`/
            `replace`/`update`/`coerce` (voir `templates.render_template`)
            ; `None` = horodatage réel.
        on_missing: Comportement de ces mêmes gabarits pour un champ
            référencé absent ("keep" ou "empty", voir `templates.py`).
    """
    try:
        for field_ref, raw_value in options.get("coerce", {}).items():
            path = parse_field_path(field_ref)
            if resolve_field(doc, path) is None:
                _assign_mutate_field(doc, field_ref, raw_value, now=now, on_missing=on_missing)
        for old_ref, new_ref in options.get("rename", {}).items():
            old_path = parse_field_path(old_ref)
            value = resolve_field(doc, old_path)
            if value is not _MISSING:
                remove_field_path(doc, old_path)
                assign_field(doc, parse_field_path(new_ref), value)
        for field_ref, raw_value in options.get("update", {}).items():
            path = parse_field_path(field_ref)
            if resolve_field(doc, path) is not _MISSING:
                _assign_mutate_field(doc, field_ref, raw_value, now=now, on_missing=on_missing)
        for key, raw_value in options.get("replace", {}).items():
            _assign_mutate_field(doc, key, raw_value, now=now, on_missing=on_missing)
        for field_ref, target_type in options.get("convert", {}).items():
            path = parse_field_path(field_ref)
            value = resolve_field(doc, path)
            if value is not _MISSING:
                assign_field(doc, path, convert_value(value, target_type, field_ref))
        gsub = options.get("gsub")
        if isinstance(gsub, list):
            apply_gsub(doc, gsub)
        for field_ref in options.get("uppercase", []):
            _apply_string_case(doc, field_ref, str.upper)
        for field_ref in options.get("capitalize", []):
            _apply_string_case(doc, field_ref, str.capitalize)
        for field_ref in options.get("lowercase", []):
            _apply_string_case(doc, field_ref, str.lower)
        for field_ref in options.get("strip", []):
            path = parse_field_path(field_ref)
            value = resolve_field(doc, path)
            if isinstance(value, str):
                assign_field(doc, path, value.strip())
        for field_ref, separator in options.get("split", {}).items():
            path = parse_field_path(field_ref)
            value = resolve_field(doc, path)
            if isinstance(value, str) and isinstance(separator, str):
                assign_field(doc, path, value.split(separator))
            elif value is not _MISSING:
                logger.debug("split impossible (champ non textuel), ignoré : {}", field_ref)
        for field_ref, separator in options.get("join", {}).items():
            path = parse_field_path(field_ref)
            value = resolve_field(doc, path)
            if isinstance(value, list) and isinstance(separator, str):
                assign_field(doc, path, separator.join(str(item) for item in value))
            elif value is not _MISSING:
                logger.debug("join impossible (champ non tableau), ignoré : {}", field_ref)
        for dest_ref, source_ref in options.get("merge", {}).items():
            _apply_merge(doc, dest_ref, source_ref)
        for source_ref, dest_ref in options.get("copy", {}).items():
            path = parse_field_path(source_ref)
            value = resolve_field(doc, path)
            if value is not _MISSING:
                assign_field(doc, parse_field_path(dest_ref), deepcopy(value))

        # Options communes à tout filtre Logstash (add_field/add_tag/
        # remove_field/remove_tag) — voir la note d'ordre ci-dessus.
        # DANS le même bloc try que les mutations ci-dessus (comme
        # `filter_matched`, appelé par le VRAI plugin dans le même begin
        # que ses propres mutations) : sautées elles aussi si une
        # exception a déjà été levée plus haut, jamais appliquées "à
        # moitié" (session 23).
        for key, raw_value in options.get("add_field", {}).items():
            _assign_mutate_field(doc, key, raw_value, now=now, on_missing=on_missing)
        add_tags = options.get("add_tag")
        if isinstance(add_tags, list):
            tags = doc.setdefault("tags", [])
            tags.extend(tag for tag in add_tags if tag not in tags)
        for field_ref in options.get("remove_field", []):
            remove_field_path(doc, parse_field_path(field_ref))
        remove_tags = options.get("remove_tag")
        if isinstance(remove_tags, list) and isinstance(doc.get("tags"), list):
            doc["tags"] = [tag for tag in doc["tags"] if tag not in remove_tags]
    except Exception as exc:  # reproduit le `rescue => ex` générique du plugin réel
        logger.warning("exception pendant l'application du filtre mutate, opérations restantes ignorées : {}", exc)
        tag_on_failure = options.get("tag_on_failure", "_mutate_error")
        if not isinstance(tag_on_failure, str):
            tag_on_failure = "_mutate_error"
        tags = doc.setdefault("tags", [])
        if tag_on_failure not in tags:
            tags.append(tag_on_failure)

    unhandled = sorted(set(options) - set(MUTATE_HANDLED_KEYS))
    if unhandled:
        logger.debug("options mutate non interprétées, ignorées : {}", unhandled)


class MutateFilter:
    """`mutate` façon Logstash (coerce/rename/update/replace/convert/gsub/uppercase/
    capitalize/lowercase/strip/split/join/merge/copy/add_field/remove_field/add_tag/remove_tag/
    tag_on_failure depuis la session 23).

    Contrairement à `Dissector`/`RegexFilter`/`KeyValueFilter`, n'attend
    aucun champ "source" textuel à extraire : opère sur le document
    ENTIER, en place — voir `FilterPipeline._compile_step`/`apply`, qui le
    reconnaît spécifiquement (comme `DropFilter`) plutôt que de le faire
    passer par le chemin source/target générique des filtres d'extraction.
    Toute la logique vit dans `apply_mutate` (ce module) — cette classe
    n'est qu'un wrapper compilé une fois par `FilterPipeline`, cohérent
    avec `Dissector`/`RegexFilter` (compilés une fois, appliqués plusieurs
    fois). Chemins de champs imbriqués façon `%{[a][b]}` acceptés partout
    depuis la session 15 — voir `apply_mutate`.
    """

    @traced
    def __init__(self, options: dict[str, Any]) -> None:
        """Mémorise les options `mutate` de cette étape (voir `apply_mutate` pour leur format)."""
        self._options = options

    @traced
    def apply(self, doc: dict[str, Any], *, now: datetime | None = None, on_missing: str = "keep") -> None:
        """Applique les options mémorisées à `doc`, en place (voir `apply_mutate`)."""
        apply_mutate(doc, self._options, now=now, on_missing=on_missing)


class GeoipFilter:
    """`geoip` façon Logstash (source/database/target/fields/tag_on_failure), pour `--filters`.

    Répond à l'item resté ouvert depuis la session 21 (voir FEATURES.md,
    "Non fait délibérément" des sessions 21-23) : `geoip` n'était implémenté
    que pour `--pipeline-conf`
    (`interpreter.py::PipelineInterpreter._apply_geoip`), pas pour
    `--filters`/`FilterPipeline`, contrairement à `mutate` (partagé entre
    les deux mécanismes depuis la session 14). Réutilise le même format de
    sortie que `_apply_geoip`/`GeoIPEnricher` (`enrichment._build_geoip_record`,
    via `enrichment.GeoIPLookup`) : UNE SEULE implémentation du schéma
    GeoIP2 pour les TROIS mécanismes de géolocalisation du projet
    (`--geoip-db`, `--pipeline-conf`, `--filters`), jamais deux qui
    pourraient diverger — même motif que `apply_mutate` (session 14) et
    `_build_geoip_record` (session 21) elle-même.

    Comme `MutateFilter`, opère sur le document ENTIER en place (résout
    lui-même `source` via `templates.resolve_field`) : `FilterPipeline`
    le reconnaît spécifiquement dans `apply()`, il ne passe donc pas par
    le chemin source/target générique des filtres d'extraction
    (`Dissector`/`RegexFilter`/`KeyValueFilter`).

    Différence assumée avec `--pipeline-conf` : `interpreter.py` ouvre sa
    base GeoIP2 PARESSEUSEMENT (au premier message qui atteint le bloc
    `geoip {}`), une base illisible étant alors journalisée en DEBUG et
    ignorée pour ce step (le fichier `.conf` reste, lui, du texte parsé
    une fois, jamais "exécuté" avant le premier message) — voir sa
    docstring. `FilterPipeline`, elle, connaît déjà TOUTES ses étapes dès
    sa construction JSON : cette classe ouvre donc la base à la
    compilation du step (`__init__`, comme `Dissector`/`RegexFilter`
    compilent leur patron), et une base `.mmdb` illisible ou un step mal
    formé (`source`/`database` absents ou non textuels) font ÉCHOUER
    `FilterPipeline(...)` tout de suite (`ValueError`) plutôt qu'au
    premier message concerné — cohérent avec le contrat déjà documenté de
    `FilterPipeline.__init__` ("Raises: ValueError: ... patron/config
    invalide") et avec `--geoip-db`/`GeoIPEnricher`, elle aussi ouverte
    eagerly au démarrage d'`omprog`. `target` prend `"geoip"` par défaut
    si absent (comme Logstash, comme `_apply_geoip`) ; `database` reste,
    lui, toujours requis explicitement (aucune base GeoLite2 embarquée
    dans ce projet, même choix que les deux autres mécanismes). Résultat
    écrit à `target` comme un REMPLACEMENT, pas une fusion (même choix
    que `_apply_geoip` — le schéma GeoIP2 officiel est un sous-objet
    autonome).
    """

    @traced
    def __init__(self, options: dict[str, Any], *, lookup_factory: Any = GeoIPLookup) -> None:
        """Résout les options du step et ouvre la base geoip.

        Args:
            options: Options du step ("source"/"database" requis,
                "target"/"fields"/"tag_on_failure" optionnels — voir la
                docstring de la classe et `interpreter.py::_apply_geoip`
                pour leur format exact, identique ici).
            lookup_factory: Callable construisant la `GeoIPLookup` à
                partir du chemin de base ; injectable pour les tests
                (double de test), comme
                `PipelineInterpreter._geoip_lookup_factory`.

        Raises:
            ValueError: "source"/"database"/"target" absents ou non
                textuels, ou base `.mmdb` illisible/invalide.
        """
        source = options.get("source")
        database = options.get("database")
        target = options.get("target", "geoip")
        if not (isinstance(source, str) and isinstance(database, str) and isinstance(target, str)):
            raise ValueError("step geoip mal formé : 'source' et 'database' (chaînes) sont requis")
        try:
            self._lookup = lookup_factory(database)
        except (OSError, maxminddb.InvalidDatabaseError) as exc:
            raise ValueError(f"base geoip illisible : {database} ({exc})") from exc
        self._source = source
        self._target = target
        self._fields = options.get("fields")
        self._tag_on_failure = options.get("tag_on_failure", ["_geoip_lookup_failure"])

    @traced
    def apply(self, doc: dict[str, Any]) -> None:
        """Géolocalise `doc[source]` et écrit le résultat sous `target`, en place.

        `tag_on_failure` (défaut `["_geoip_lookup_failure"]`, comme
        Logstash) signale par un tag dans `doc["tags"]` une IP absente/non
        textuelle ou sans correspondance dans la base — `target` reste
        alors inchangé, exactement comme `interpreter.py::_apply_geoip`.
        """
        ip = resolve_field(doc, parse_field_path(self._source))
        if not isinstance(ip, str):
            add_failure_tags(doc, self._tag_on_failure)
            return
        record = self._lookup.lookup(ip)
        if not record:
            add_failure_tags(doc, self._tag_on_failure)
            return
        fields = self._fields
        if isinstance(fields, list) and fields:
            record = {key: value for key, value in record.items() if key in fields}
        assign_field(doc, parse_field_path(self._target), record)

    @traced
    def close(self) -> None:
        """Ferme la base geoip. Voir `FilterPipeline.close`."""
        self._lookup.close()


class TranslateFilter:
    """`translate` façon Logstash (dictionary_path/source/target/fallback), pour `--filters`.

    Répond à un item resté ouvert depuis la session 16 (`translate`/`mmdb`/
    `date` implémentés SEULEMENT pour `--pipeline-conf`, voir FEATURES.md,
    "Non fait délibérément" des sessions 21-24) : comme `mutate` (session 14)
    et `geoip` (session 24) avant lui, `translate` est désormais partagé
    entre les deux mécanismes de filtrage du projet. Choisi comme candidat
    de cette session plutôt que `mmdb`/`date` : c'est le SEUL des trois
    réellement utilisé dans le pipeline `.conf` réel de Mathilde
    (`pipeline.example.d/25_filter_logstash-rsyslog-dns-geoip.conf`), et
    utilisé trois fois (`ifName`/`ifNamevlan`/`ifSupervision`), toujours
    avec un `fallback` sprintf — voir CLAUDE.md, entrée "Session 25", et
    PATTERNS.md pour le détail de ce choix.

    Réutilise `enrichment.TranslateDictionary` — même chargement/recherche
    que `interpreter.py::PipelineInterpreter._apply_translate` — donc AUCUNE
    nouvelle arête de dépendances : `filters -> enrichment` existe déjà
    depuis la session 24 (`GeoIPLookup`). Contrairement à `GeoipFilter`,
    n'expose PAS de `close()` : `TranslateDictionary` charge son fichier
    YAML une seule fois en mémoire à la construction et ne garde ensuite
    aucune ressource externe ouverte (pas de `Reader` façon `maxminddb`/
    `geoip2`) — voir sa docstring dans `enrichment.py`.

    Comme `GeoipFilter`, opère sur le document ENTIER en place (résout
    lui-même `source`, chemin `%{[a][b]}` éventuellement imbriqué — le
    pipeline réel de Mathilde utilise `source => "[@metadata][...]"`, pas
    un champ plat) : `FilterPipeline` le reconnaît spécifiquement, il ne
    passe donc pas par le chemin source/target générique des filtres
    d'extraction (`Dissector`/`RegexFilter`/`KeyValueFilter`).

    Différence assumée avec `--pipeline-conf` (même principe que
    `GeoipFilter`) : `interpreter.py` charge son dictionnaire YAML
    PARESSEUSEMENT (au premier message concerné, fichier illisible ignoré
    en DEBUG) — `FilterPipeline` connaît déjà TOUTES ses étapes dès sa
    construction JSON, cette classe charge donc le dictionnaire à la
    COMPILATION du step (`__init__`, comme `Dissector`/`RegexFilter`
    compilent leur patron, ou `GeoipFilter` ouvre sa base) : un fichier YAML
    introuvable/malformé fait ÉCHOUER `FilterPipeline(...)` tout de suite
    (`ValueError`), cohérent avec son contrat déjà documenté. `fallback`
    (gabarit sprintf éventuel, ex. `"index: %{[ifTable][index]}"`) est rendu
    via `templates.render_template` — comme `MutateFilter.apply`, cette
    méthode a donc besoin de `now`/`on_missing` (contrairement à
    `GeoipFilter`, qui ne rend aucun gabarit) : `FilterPipeline.apply` les
    lui transmet. `refresh_behaviour` (ex. "replace" dans le pipeline réel)
    reste, comme pour `--pipeline-conf`, jamais honoré — un seul
    `TranslateDictionary` chargé une fois par step, voir FEATURES.md,
    "Limites connues".
    """

    @traced
    def __init__(self, options: dict[str, Any], *, dictionary_factory: Any = TranslateDictionary) -> None:
        """Résout les options du step et charge le dictionnaire YAML.

        Args:
            options: Options du step ("dictionary_path"/"source"/"target"
                requis, "fallback" optionnel — voir la docstring de la
                classe et `interpreter.py::_apply_translate` pour leur
                format exact, identique ici).
            dictionary_factory: Callable construisant le
                `enrichment.TranslateDictionary` à partir du chemin de
                fichier ; injectable pour les tests (double de test), comme
                `PipelineInterpreter._translate_dictionary_factory`.

        Raises:
            ValueError: "dictionary_path"/"source"/"target" absents ou non
                textuels, ou fichier YAML illisible/malformé.
        """
        dictionary_path = options.get("dictionary_path")
        source = options.get("source")
        target = options.get("target")
        if not (isinstance(dictionary_path, str) and isinstance(source, str) and isinstance(target, str)):
            raise ValueError("step translate mal formé : 'dictionary_path', 'source' et 'target' (chaînes) sont requis")
        try:
            self._dictionary = dictionary_factory(dictionary_path)
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"dictionnaire translate illisible : {dictionary_path} ({exc})") from exc
        self._source = source
        self._target = target
        self._fallback = options.get("fallback")

    @traced
    def apply(self, doc: dict[str, Any], *, now: datetime | None = None, on_missing: str = "keep") -> None:
        """Recherche `doc[source]` dans le dictionnaire et écrit le résultat sous `target`, en place.

        Sans correspondance : rend `fallback` comme gabarit sprintf (si
        c'est une chaîne) ou l'utilise tel quel, et l'écrit à `target` —
        exactement comme `interpreter.py::_apply_translate`. Sans
        `fallback` et sans correspondance, `target` n'est pas touché.
        """
        key = resolve_field(doc, parse_field_path(self._source))
        value = self._dictionary.lookup(key) if key is not _MISSING else None
        if value is None:
            fallback = self._fallback
            if fallback is None:
                return
            if isinstance(fallback, str):
                value = render_template(fallback, doc, now=now, on_missing=on_missing)
            else:
                value = fallback
        assign_field(doc, parse_field_path(self._target), value)


@traced
def load_word_list(path: str) -> list[str]:
    """Charge une liste de mots depuis un fichier texte.

    Args:
        path: Chemin du fichier, un motif par ligne ; lignes vides et lignes
            commençant par "#" ignorées.

    Returns:
        La liste des motifs, dans l'ordre du fichier.
    """
    words: list[str] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                words.append(stripped)
    return words


class FilterPipeline:
    """Chaîne de filtres façon Logstash (dissect, regex, kv, drop, mutate, geoip, translate), appliqués en séquence."""

    @traced
    def __init__(
        self,
        steps: list[dict],
        *,
        geoip_lookup_factory: Any = GeoIPLookup,
        translate_dictionary_factory: Any = TranslateDictionary,
    ) -> None:
        """Compile la chaîne de filtres.

        Args:
            steps: Liste ordonnée de définitions de filtre, chacune avec au
                moins "type" ("dissect", "regex", "kv", "drop", "mutate"
                (depuis la session 14), "geoip" (depuis la session 24) ou
                "translate" (depuis la session 25) et, sauf pour "mutate"/
                "geoip"/"translate", "source" (champ du document à
                analyser). "dissect"/"regex"/"kv" acceptent en plus "target"
                (sous-objet dans lequel placer les champs extraits ; à
                défaut, fusionnés au premier niveau). "drop" attend
                "words_file" (fichier texte, un motif par ligne) ou "words"
                (liste inline), et accepte "mode" ("equals"/"contains",
                "contains" par défaut) et "case_sensitive" (false par
                défaut). "mutate" n'attend PAS de "source"/"target" (il
                opère sur le document entier) : voir `apply_mutate` pour le
                format de ses propres clés ("rename"/"convert"/"gsub"/
                "strip"/"add_field"/"remove_field"/"add_tag"/"remove_tag").
                "geoip" attend "source"/"database" (requis) et
                "target"/"fields"/"tag_on_failure" (optionnels) : voir
                `GeoipFilter` pour le détail, identique à `interpreter.py::
                _apply_geoip`. "translate" attend "dictionary_path"/
                "source"/"target" (requis) et "fallback" (optionnel) : voir
                `TranslateFilter` pour le détail, identique à
                `interpreter.py::_apply_translate`. Voir
                filters.example.json et blocklist.example.txt.
            geoip_lookup_factory: Callable construisant une
                `enrichment.GeoIPLookup` à partir d'un chemin de base,
                utilisée par tout step "geoip" de `steps` ; injectable pour
                les tests (double de test), comme
                `PipelineInterpreter._geoip_lookup_factory`.
            translate_dictionary_factory: Callable construisant un
                `enrichment.TranslateDictionary` à partir d'un chemin de
                fichier YAML, utilisée par tout step "translate" de
                `steps` ; injectable pour les tests, comme
                `PipelineInterpreter._translate_dictionary_factory`.

        Raises:
            ValueError: Type de filtre inconnu, patron/config invalide, ou
                (depuis la session 24) step "geoip" mal formé/base `.mmdb`
                illisible, ou (depuis la session 25) step "translate" mal
                formé/dictionnaire YAML illisible.
        """
        self._geoip_lookup_factory = geoip_lookup_factory
        self._translate_dictionary_factory = translate_dictionary_factory
        self._steps = [self._compile_step(step) for step in steps]

    @traced
    def _compile_step(self, step: dict) -> tuple[str | None, object, str | None]:
        """Précompile une étape (champ source, filtre compilé, champ cible).

        "mutate" (session 14), "geoip" (session 24) et "translate" (session
        25) sont des cas à part : ils ne lisent ni "source" ni "target" au
        sens générique (contrairement à dissect/regex/kv, qui extraient
        TOUJOURS d'un champ texte unique vers un champ/sous-objet cible —
        "geoip"/"translate" résolvent eux-mêmes leur "source", à un chemin
        imbriqué possible, voir `GeoipFilter.apply`/`TranslateFilter.apply`),
        donc leur "source" renvoyé est `None` — `apply()` les reconnaît par
        type (`isinstance(compiled, ...)`) avant même de regarder `source`,
        comme il le fait déjà pour `DropFilter`.
        """
        filter_type = step["type"]
        if filter_type == "mutate":
            # "_comment" est une convention documentaire du projet (voir
            # filters.example.json), pas une option mutate : exclue comme
            # "type", pour ne pas polluer le log "options mutate non
            # interprétées" d'apply_mutate avec une fausse alerte.
            options = {key: value for key, value in step.items() if key not in ("type", "_comment")}
            return None, MutateFilter(options), None
        if filter_type == "geoip":
            options = {key: value for key, value in step.items() if key not in ("type", "_comment")}
            return None, GeoipFilter(options, lookup_factory=self._geoip_lookup_factory), None
        if filter_type == "translate":
            options = {key: value for key, value in step.items() if key not in ("type", "_comment")}
            return None, TranslateFilter(options, dictionary_factory=self._translate_dictionary_factory), None
        source = step["source"]
        target = step.get("target")
        if filter_type == "dissect":
            compiled: object = Dissector(step["pattern"])
        elif filter_type == "regex":
            compiled = RegexFilter(step["pattern"])
        elif filter_type == "kv":
            compiled = KeyValueFilter(
                field_split=step.get("field_split", " "),
                value_split=step.get("value_split", "="),
                prefix=step.get("prefix", ""),
            )
        elif filter_type == "drop":
            if "words_file" in step:
                words = load_word_list(step["words_file"])
            elif "words" in step:
                words = step["words"]
            else:
                raise ValueError("filtre drop sans 'words_file' ni 'words'")
            compiled = DropFilter(
                words=words,
                mode=step.get("mode", "contains"),
                case_sensitive=step.get("case_sensitive", False),
            )
        else:
            raise ValueError(f"type de filtre inconnu: {filter_type!r}")
        return source, compiled, target

    @traced
    def apply(self, doc: dict, *, now: datetime | None = None, on_missing: str = "keep") -> bool:
        """Applique chaque filtre de la chaîne à doc, en place.

        Un filtre "dissect"/"regex"/"kv" dont le champ source est absent, non
        textuel, ou dont le patron ne correspond pas est ignoré pour ce
        message (log en DEBUG) plutôt que de faire échouer tout le document.
        Un filtre "drop" qui correspond arrête immédiatement la chaîne. Un
        filtre "mutate" (session 14), "geoip" (session 24) ou "translate"
        (session 25) s'applique inconditionnellement au document entier (pas
        de notion de "correspondance" au sens de dissect/regex/kv — "geoip"/
        "translate" ont chacun leur propre notion d'échec, gérée par
        `tag_on_failure`/`fallback`, voir `GeoipFilter.apply`/
        `TranslateFilter.apply`).

        Args:
            doc: Document à enrichir, modifié en place.
            now: Horodatage transmis à un éventuel step "mutate"/"translate"
                pour le rendu des gabarits sprintf de son option
                "add_field"/"fallback" (voir `apply_mutate`/
                `TranslateFilter.apply`) ; `None` = horodatage réel.
            on_missing: Idem, comportement pour un champ référencé absent
                dans un gabarit "add_field"/"fallback" ("keep" ou "empty").

        Returns:
            False si un filtre "drop" a demandé l'abandon du document
            (aucun traitement ultérieur ne doit avoir lieu), True sinon.
        """
        for source, compiled, target in self._steps:
            if isinstance(compiled, MutateFilter):
                compiled.apply(doc, now=now, on_missing=on_missing)
                continue
            if isinstance(compiled, GeoipFilter):
                compiled.apply(doc)
                continue
            if isinstance(compiled, TranslateFilter):
                compiled.apply(doc, now=now, on_missing=on_missing)
                continue
            value = doc.get(source)
            if not isinstance(value, str):
                continue
            if isinstance(compiled, DropFilter):
                if compiled.matches(value):
                    return False
                continue
            extracted = compiled.apply(value)
            if extracted is None:
                logger.debug("filtre sans correspondance source={source!r}", source=source)
                continue
            if target:
                doc.setdefault(target, {}).update(extracted)
            else:
                doc.update(extracted)
        return True

    @traced
    def close(self) -> None:
        """Ferme toute base geoip ouverte par un step "geoip" de cette chaîne (session 24).

        Sans effet si la chaîne ne contient aucun step "geoip" (aucune
        `GeoIPLookup` créée). Symétrique de
        `PipelineInterpreter.close_geoip_lookups` (`--pipeline-conf`) et de
        `GeoIPEnricher.close` (`--geoip-db`) — les TROIS mécanismes de
        géolocalisation du projet exposent désormais un `close()`.
        """
        for _source, compiled, _target in self._steps:
            if isinstance(compiled, GeoipFilter):
                compiled.close()
