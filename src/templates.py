"""Lecture et interprétation des templates Logstash (syntaxe "sprintf", %{...}).

Module autonome et réutilisable : ne connaît rien d'omprog, de rsyslog ni
d'OpenSearch — juste comment un gabarit texte façon Logstash se compile et
se rend contre un document (dict) événement. Prévu pour être importé par
n'importe quel module qui a besoin de produire dynamiquement un index, un
document_id, un chemin de fichier ou un champ texte comme le ferait
Logstash (`indexer.py` l'utilise pour `--document-id-template`).

Grammaire couverte (voir le document de référence transmis par Mathilde,
sections 1-6 et 9-12 ; la section 7, conditions `if [champ] == ...`,
appartient au DSL des blocs filter{}/output{}, pas à la syntaxe "template"
au sens sprintf, et n'est délibérément pas traitée ici) :

    %{champ}                référence de champ simple
    %{[objet][champ]}       référence de champ imbriqué (un niveau par
                             paire de crochets)
    %{[@metadata][champ]}   référence dans @metadata (mêmes règles de
                             chemin ; @metadata est un champ racine comme
                             un autre du point de vue du gabarit)
    %{[tableau][0]}         indexation d'un tableau (segment de chemin
                             numérique)
    %{+FORMAT}               date basée sur @timestamp, ancienne syntaxe
                             (ex. %{+YYYY.MM.dd})
    %{{FORMAT}}               date basée sur @timestamp, syntaxe Java Time
                             recommandée (ex. %{{yyyy.MM.dd}})
    %{{TIME_NOW}}             heure du traitement (pas @timestamp)
    texte fixe autour        conservé tel quel ; plusieurs références
                             possibles dans un même gabarit

Champ absent (section 11 du document) : Logstash ne garantit pas un
comportement unique ("peut conserver littéralement ... ou générer une
valeur vide") — `render()` expose ce choix via `on_missing` ("keep" par
défaut, conserve le "%{...}" littéral ; "empty" pour une chaîne vide)
plutôt que de trancher silencieusement à la place de l'appelant. Un champ
présent mais explicitement `null` se rend toujours en chaîne vide (comme
un `to_s` Ruby de `nil`), indépendamment de `on_missing`.

Limites assumées (voir FEATURES.md) :
    - Modes d'échappement de noms de champs contenant eux-mêmes des
      crochets (section 12 : none/percent/ampersand) non implémentés —
      cas non rencontré dans les logs HPE Comware qui motivent ce projet.
    - Le format Java Time n'est pas réimplémenté dans sa généralité (pas
      d'équivalent Python de `java.time.DateTimeFormatter`) : seuls les
      motifs lettre par lettre usuels des exemples du document (y, M, d,
      H, m, s, S, X/Z pour le décalage horaire, et le texte littéral entre
      quotes simples façon 'T') sont traduits — voir `_format_letter_run`.
      Une lettre hors de cette liste (ex. `E` jour de semaine, `W` semaine
      de l'année) est recopiée telle quelle plutôt que de lever une
      exception : repli sans surprise, pas un échec silencieux qui
      tronquerait le résultat.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from loguru import logger

from tracing import traced

_MISSING = object()  # sentinelle : distingue "champ absent" de "champ présent valant None"


@dataclass(frozen=True)
class _Token:
    """Un fragment de gabarit déjà classifié (littéral, référence, ou date)."""

    kind: str  # "literal" | "field" | "olddate" | "newdate"
    value: str


@dataclass(frozen=True)
class CompiledTemplate:
    """Un gabarit Logstash déjà découpé en tokens, prêt à être rendu plusieurs fois sans reparser.

    Réutiliser une même `CompiledTemplate` pour rendre de nombreux
    documents (ex. un `document_id` par message reçu) évite de
    retokeniser la chaîne de gabarit à chaque appel.
    """

    source: str
    tokens: tuple[_Token, ...]


@traced
def compile_template(source: str) -> CompiledTemplate:
    """Découpe un gabarit Logstash en tokens.

    Args:
        source: Le gabarit brut, ex. "logs-%{[service][name]}-%{+YYYY.MM.dd}".

    Returns:
        Le gabarit compilé, à passer à `render()`.
    """
    return CompiledTemplate(source, tuple(_tokenize(source)))


@traced
def render(
    compiled: CompiledTemplate,
    event: dict[str, Any],
    *,
    now: datetime | None = None,
    on_missing: str = "keep",
) -> str:
    """Rend un gabarit déjà compilé contre un document événement.

    Args:
        compiled: Résultat de `compile_template`.
        event: Document événement (dict), ex. {"client_ip": "1.2.3.4", ...}.
        now: Horodatage à utiliser pour %{{TIME_NOW}} et comme repli pour
            %{+FORMAT}/%{{FORMAT}} si `event` n'a pas de "@timestamp"
            exploitable. Par défaut `datetime.now(timezone.utc)`.
        on_missing: "keep" (défaut, conserve "%{...}" littéral) ou "empty"
            (chaîne vide) pour une référence de champ dont le chemin ne
            résout à rien dans `event` (section 11 du document de
            référence).

    Returns:
        Le texte rendu.

    Raises:
        ValueError: `on_missing` autre que "keep"/"empty".
    """
    if on_missing not in ("keep", "empty"):
        raise ValueError(f"on_missing inconnu: {on_missing!r} (attendu 'keep' ou 'empty')")
    moment = now if now is not None else datetime.now(timezone.utc)
    parts: list[str] = []
    for token in compiled.tokens:
        if token.kind == "literal":
            parts.append(token.value)
        elif token.kind == "field":
            parts.append(_render_field(token.value, event, on_missing))
        elif token.kind == "olddate":
            parts.append(_format_timestamp(token.value, _event_timestamp(event, moment)))
        elif token.kind == "newdate":
            if token.value == "TIME_NOW":
                parts.append(_format_timestamp("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", moment))
            else:
                parts.append(_format_timestamp(token.value, _event_timestamp(event, moment)))
    return "".join(parts)


@traced
def render_template(
    source: str,
    event: dict[str, Any],
    *,
    now: datetime | None = None,
    on_missing: str = "keep",
) -> str:
    """Raccourci `compile_template` + `render` pour un gabarit utilisé une seule fois.

    Pour un gabarit réutilisé sur de nombreux documents (ex. dans une
    boucle de traitement), préférer `compile_template` une fois puis
    `render` à chaque document : évite de retokeniser à chaque appel.
    """
    return render(compile_template(source), event, now=now, on_missing=on_missing)


@traced
def parse_field_path(expr: str) -> list[str]:
    """Interprète l'intérieur d'une référence %{...} en chemin de champ.

    Args:
        expr: Contenu entre "%{" et "}", ex. "client_ip" ou
            "[service][name]" ou "[tags][0]".

    Returns:
        Le chemin sous forme de liste de segments, ex. ["service", "name"].
        Une référence simple (sans crochets) donne une liste à un élément.

    Raises:
        ValueError: Référence vide, ou chemin entre crochets mal formé
            (crochet non refermé, ou texte parasite entre deux groupes).
    """
    expr = expr.strip()
    if not expr:
        raise ValueError("référence de champ vide: %{}")
    if not expr.startswith("["):
        return [expr]
    segments: list[str] = []
    rest = expr
    while rest:
        if not rest.startswith("["):
            raise ValueError(f"chemin de champ mal formé (texte hors crochets): {expr!r}")
        end = rest.find("]")
        if end == -1:
            raise ValueError(f"crochet non refermé dans le chemin de champ: {expr!r}")
        segments.append(rest[1:end])
        rest = rest[end + 1 :]
    return segments


@traced
def resolve_field(event: Any, path: list[str]) -> Any:
    """Suit un chemin de champ dans un document (dict imbriqué et/ou listes).

    Args:
        event: Document événement (ou toute valeur imbriquée en cours de
            parcours — dict, liste, ou scalaire).
        path: Chemin tel que renvoyé par `parse_field_path`.

    Returns:
        La valeur trouvée (qui peut être `None` si le champ vaut
        explicitement `null`), ou la sentinelle interne `_MISSING` si le
        chemin ne résout à rien (clé absente, indice hors limites, ou
        chemin qui continue sur un scalaire).
    """
    current: Any = event
    for step in path:
        if isinstance(current, dict):
            if step not in current:
                return _MISSING
            current = current[step]
        elif isinstance(current, (list, tuple)):
            if not step.lstrip("-").isdigit():
                return _MISSING
            index = int(step)
            if -len(current) <= index < len(current):
                current = current[index]
            else:
                return _MISSING
        else:
            return _MISSING
    return current


@traced
def assign_field(event: dict[str, Any], path: list[str], value: Any) -> None:
    """Écrit `value` au chemin `path` dans `event`, en créant les dictionnaires imbriqués manquants.

    Nouveauté session 15, en réponse à un pipeline `.conf` de production
    réel transmis par Mathilde : chaque bloc `mutate { add_field => {
    "[syslog][name]" => ... } }` de ce pipeline cible un champ imbriqué,
    jamais une clé plate — sans cette fonction, `apply_mutate`
    (`filters.py`) écrivait littéralement une clé `"[syslog][name]"` au
    premier niveau du document au lieu de `doc["syslog"]["name"]`.

    Suit le même chemin que `resolve_field`, mais en ÉCRITURE : un segment
    intermédiaire absent ou qui ne vaut ni dict ni liste devient un
    nouveau dict (jamais une liste — créer une liste de la bonne taille à
    partir d'un simple indice numérique serait deviner une intention que
    rien dans un `%{...}`/mutate ne précise). Un chemin qui traverse un
    indice de liste hors limites est abandonné (log en DEBUG) plutôt que
    d'agrandir la liste ou de lever une exception : même philosophie que
    `FilterPipeline.apply` pour un filtre sans correspondance.

    Args:
        event: Document à modifier en place.
        path: Chemin tel que renvoyé par `parse_field_path`. Un chemin
            vide ne fait rien (rien à nommer).
        value: Valeur à écrire au segment final.
    """
    if not path:
        return
    current: Any = event
    for step in path[:-1]:
        if isinstance(current, dict):
            nxt = current.get(step)
            if not isinstance(nxt, (dict, list)):
                nxt = {}
                current[step] = nxt
            current = nxt
        elif isinstance(current, list):
            if not step.lstrip("-").isdigit() or not (-len(current) <= int(step) < len(current)):
                logger.debug("chemin de champ hors limites, écriture abandonnée : {}", path)
                return
            current = current[int(step)]
        else:
            logger.debug("chemin de champ traverse un scalaire, écriture abandonnée : {}", path)
            return
    last = path[-1]
    if isinstance(current, dict):
        current[last] = value
    elif isinstance(current, list):
        if last.lstrip("-").isdigit() and -len(current) <= int(last) < len(current):
            current[int(last)] = value
        else:
            logger.debug("indice de liste hors limites, écriture abandonnée : {}", path)
    else:
        logger.debug("chemin de champ traverse un scalaire, écriture abandonnée : {}", path)


@traced
def remove_field_path(event: dict[str, Any], path: list[str]) -> None:
    """Retire le champ situé à `path` dans `event`, sans erreur s'il est déjà absent.

    Nouveauté session 15 (voir `assign_field`) : équivalent imbriqué de
    `doc.pop(field_name, None)`, pour `mutate.remove_field` sur un champ
    comme `"[hostTable][index]"`. Seul le dict parent immédiat peut perdre
    une clé — retirer un élément d'une LISTE parente décalerait les
    indices suivants de façon surprenante pour l'appelant, donc ce cas est
    ignoré (log en DEBUG) plutôt que traité.

    Args:
        event: Document à modifier en place.
        path: Chemin tel que renvoyé par `parse_field_path`. Un chemin
            vide ne fait rien.
    """
    if not path:
        return
    parent = event if len(path) == 1 else resolve_field(event, path[:-1])
    if isinstance(parent, dict):
        parent.pop(path[-1], None)
    elif parent is not _MISSING and not isinstance(parent, dict):
        logger.debug("parent du champ n'est pas un dict, suppression ignorée : {}", path)


@traced
def _render_field(inner: str, event: dict[str, Any], on_missing: str) -> str:
    """Rend une seule référence %{...} (hors dates)."""
    path = parse_field_path(inner)
    value = resolve_field(event, path)
    if value is _MISSING:
        return f"%{{{inner}}}" if on_missing == "keep" else ""
    if value is None:
        return ""
    return str(value)


@traced
def _tokenize(source: str) -> list[_Token]:
    """Découpe un gabarit brut en tokens (littéral / field / olddate / newdate).

    Distingue %{{...}} (syntaxe Java Time / TIME_NOW, cherché en premier
    pour ne pas être pris pour un simple %{...}) de %{...} (référence de
    champ, ou date ancienne syntaxe si le contenu commence par "+"). Un
    "%{" ou "%{{" jamais refermé est recopié tel quel comme texte littéral
    plutôt que de lever une exception : un gabarit légèrement malformé ne
    doit pas faire planter tout l'appelant.
    """
    tokens: list[_Token] = []
    i = 0
    n = len(source)
    literal_start = 0
    while i < n:
        if source[i] == "%" and i + 1 < n and source[i + 1] == "{":
            if i > literal_start:
                tokens.append(_Token("literal", source[literal_start:i]))
            if i + 2 < n and source[i + 2] == "{":
                end = source.find("}}", i + 3)
                if end == -1:
                    tokens.append(_Token("literal", source[i:]))
                    i = n
                    literal_start = n
                    continue
                tokens.append(_Token("newdate", source[i + 3 : end]))
                i = end + 2
                literal_start = i
                continue
            end = source.find("}", i + 2)
            if end == -1:
                tokens.append(_Token("literal", source[i:]))
                i = n
                literal_start = n
                continue
            inner = source[i + 2 : end]
            if inner.startswith("+"):
                tokens.append(_Token("olddate", inner[1:]))
            else:
                tokens.append(_Token("field", inner))
            i = end + 1
            literal_start = i
            continue
        i += 1
    if literal_start < n:
        tokens.append(_Token("literal", source[literal_start:n]))
    return tokens


@traced
def _event_timestamp(event: dict[str, Any], fallback: datetime) -> datetime:
    """Extrait "@timestamp" de `event` comme datetime aware, ou renvoie `fallback`."""
    raw = event.get("@timestamp") if isinstance(event, dict) else None
    if not raw:
        return fallback
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return fallback
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return fallback


@traced
def _format_timestamp(pattern: str, dt: datetime) -> str:
    """Formate `dt` selon un motif de date façon Joda/Java Time (voir `_split_date_pattern`)."""
    return "".join(
        text if kind == "literal" else _format_letter_run(text, dt) for kind, text in _split_date_pattern(pattern)
    )


@traced
def _split_date_pattern(pattern: str) -> list[tuple[str, str]]:
    """Découpe un motif de date en runs de lettres identiques et texte littéral.

    Gère les littéraux entre quotes simples de la convention Joda/Java
    Time ('T' -> le caractère T tel quel, '' -> un guillemet simple
    littéral) en plus du texte déjà non-alphabétique (ex. "-", ":", ".").
    """
    tokens: list[tuple[str, str]] = []
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "'":
            j = i + 1
            buf: list[str] = []
            closed = False
            while j < n:
                if pattern[j] == "'":
                    if j + 1 < n and pattern[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    j += 1
                    closed = True
                    break
                buf.append(pattern[j])
                j += 1
            tokens.append(("literal", "".join(buf) if buf else "'"))
            i = j if closed else n
        elif ch.isalpha():
            j = i
            while j < n and pattern[j] == ch:
                j += 1
            tokens.append(("field", pattern[i:j]))
            i = j
        else:
            j = i
            while j < n and pattern[j] != "'" and not pattern[j].isalpha():
                j += 1
            tokens.append(("literal", pattern[i:j]))
            i = j
    return tokens


@traced
def _format_letter_run(run: str, dt: datetime) -> str:
    """Formate un run de lettres identiques (ex. "yyyy", "SSS") pour `dt`."""
    letter = run[0]
    length = len(run)
    if letter in ("y", "Y"):
        return f"{dt.year % 100:02d}" if length <= 2 else f"{dt.year:0{max(length, 4)}d}"
    if letter == "M":
        return f"{dt.month:0{length}d}"
    if letter == "d":
        return f"{dt.day:0{length}d}"
    if letter == "H":
        return f"{dt.hour:0{length}d}"
    if letter == "m":
        return f"{dt.minute:0{length}d}"
    if letter == "s":
        return f"{dt.second:0{length}d}"
    if letter == "S":
        millis = f"{dt.microsecond // 1000:03d}"
        return millis[:length] if length <= 3 else millis.ljust(length, "0")
    if letter in ("X", "x", "Z", "z"):
        return _format_offset(dt, letter, length)
    # Lettre non gérée (ex. E jour de semaine, W semaine de l'année) :
    # recopiée telle quelle — voir la docstring du module, "Limites assumées".
    return run


@traced
def _format_offset(dt: datetime, letter: str, length: int) -> str:
    """Formate le décalage UTC de `dt` façon Java Time X/Z (voir la docstring du module)."""
    offset = dt.utcoffset() or timedelta(0)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    hours, minutes = divmod(total_minutes, 60)
    is_zero = hours == 0 and minutes == 0
    if letter.upper() == "X":
        if is_zero:
            return "Z"
        if length == 1:
            return f"{sign}{hours:02d}"
        if length == 2:
            return f"{sign}{hours:02d}{minutes:02d}"
        return f"{sign}{hours:02d}:{minutes:02d}"
    # Z/z (style RFC 822) : jamais "Z" littéral pour un décalage nul.
    if length >= 4:
        return f"{sign}{hours:02d}:{minutes:02d}"
    return f"{sign}{hours:02d}{minutes:02d}"
