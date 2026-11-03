# SPDX-License-Identifier: GPL-3.0-or-later
"""Filtre `grok` natif de Logstash (#112) : motifs `%{SYNTAXE:champ:type}`.

Bibliothèque de motifs : sous-ensemble des motifs « legacy » de
logstash-patterns-core (`patterns/legacy/grok-patterns`, Apache-2.0,
https://github.com/logstash-plugins/logstash-patterns-core), adaptés à
`re` de Python :

- `(?<nom>…)` (Oniguruma) devient `(?P<nom>…)` ; les groupes atomiques
  `(?>…)` sont acceptés tels quels (Python ≥ 3.11) ;
- les classes POSIX `[[:alnum:]]` deviennent `[^\\W]` ; la coquille
  `(?!<[0-9])` du motif `TIME` d'origine est écrite `(?<![0-9])`.

Comportement repris du plugin officiel (`logstash-filter-grok`) :

- `match` : `{ champ => motif | [motifs] }` ou l'ancienne forme
  `[champ, motif, …]` ; les motifs sont essayés dans l'ordre ;
  `break_on_match` (vrai par défaut) arrête au premier qui correspond ;
- `%{SYNTAXE}` ne capture rien, `%{SYNTAXE:champ}` capture (chemin
  `[a][b]` accepté), `%{SYNTAXE:champ:int|float}` convertit ; les
  captures nommées des sous-motifs (ex. `program` et `pid` de
  `SYSLOGPROG`) sont aussi des champs, comme en mode legacy ;
- `pattern_definitions` (motifs en ligne) et `patterns_dir` (fichiers
  `NOM regex`, une définition par ligne, `#` en commentaire) ;
- `overwrite` : un champ déjà présent est remplacé seulement s'il y est
  cité ; sinon la nouvelle valeur s'ajoute (le champ devient un tableau),
  comme `event.set` + `append` du plugin ;
- `keep_empty_captures` (faux par défaut) : une capture vide est ignorée ;
- `target` : captures écrites sous ce champ plutôt qu'à la racine ;
- `tag_on_failure` (`["_grokparsefailure"]` par défaut).

Non repris : `timeout_millis` / `timeout_scope` (pas de délai d'arrêt
d'une regex en Python), `ecs_compatibility` (motifs legacy seulement),
`named_captures_only => false`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from loguru import logger

from i18n import _
from templates import _MISSING, assign_field, parse_field_path, resolve_field
from tracing import traced
from util import add_failure_tags

#: Motifs de base (logstash-patterns-core, legacy/grok-patterns, Apache-2.0).
BASE_PATTERNS: dict[str, str] = {
    "USERNAME": r"[a-zA-Z0-9._-]+",
    "USER": r"%{USERNAME}",
    "EMAILLOCALPART": r"[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]{1,64}(?:\.[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~]{1,62}){0,63}",
    "EMAILADDRESS": r"%{EMAILLOCALPART}@%{HOSTNAME}",
    "INT": r"(?:[+-]?(?:[0-9]+))",
    "BASE10NUM": r"(?<![0-9.+-])(?>[+-]?(?:(?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+)))",
    "NUMBER": r"(?:%{BASE10NUM})",
    "BASE16NUM": r"(?<![0-9A-Fa-f])(?:[+-]?(?:0x)?(?:[0-9A-Fa-f]+))",
    "BASE16FLOAT": r"\b(?<![0-9A-Fa-f.])(?:[+-]?(?:0x)?(?:(?:[0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?)|(?:\.[0-9A-Fa-f]+)))\b",
    "POSINT": r"\b(?:[1-9][0-9]*)\b",
    "NONNEGINT": r"\b(?:[0-9]+)\b",
    "WORD": r"\b\w+\b",
    "NOTSPACE": r"\S+",
    "SPACE": r"\s*",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "QUOTEDSTRING": (r"(?>(?<!\\)(?>\"(?>\\.|[^\\\"]+)+\"|\"\"|(?>'(?>\\.|[^\\']+)+')|''|(?>`(?>\\.|[^\\`]+)+`)|``))"),
    "UUID": r"[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}",
    "URN": r"urn:[0-9A-Za-z][0-9A-Za-z-]{0,31}:(?:%[0-9a-fA-F]{2}|[0-9A-Za-z()+,.:=@;$_!*'/?#-])+",
    "CISCOMAC": r"(?:(?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4})",
    "WINDOWSMAC": r"(?:(?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2})",
    "COMMONMAC": r"(?:(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})",
    "MAC": r"(?:%{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC})",
    "IPV4": (
        r"(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])"
        r"[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])"
    ),
    "IPV6": (
        r"(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,4}:%{IPV4}"
        r"|::(?:[Ff]{4}(?::0{1,4})?:)?%{IPV4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
        r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
        r"|[Ff][Ee]80:(?::[0-9A-Fa-f]{0,4}){0,4}%[0-9A-Za-z]+"
        r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
        r"|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))"
    ),
    "IP": r"(?:%{IPV6}|%{IPV4})",
    "HOSTNAME": r"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(?:\.?|\b)",
    "IPORHOST": r"(?:%{IP}|%{HOSTNAME})",
    "HOSTPORT": r"%{IPORHOST}:%{POSINT}",
    "UNIXPATH": r"(?:/[\w%!$@:.,+~-]*)+",
    "TTY": r"(?:/dev/(?:pts|tty(?:[pq])?)(?:\w+)?/?(?:[0-9]+))",
    "WINPATH": r"(?>[A-Za-z]+:|\\)(?:\\[^\\?*]*)+",
    "PATH": r"(?:%{UNIXPATH}|%{WINPATH})",
    "URIPROTO": r"[A-Za-z](?:[A-Za-z0-9+\-.]+)+",
    "URIHOST": r"%{IPORHOST}(?::%{POSINT})?",
    "URIPATH": r"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\-]*)+",
    "URIQUERY": r"[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*",
    "URIPARAM": r"\?%{URIQUERY}",
    "URIPATHPARAM": r"%{URIPATH}(?:\?%{URIQUERY})?",
    "URI": r"%{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATH}(?:\?%{URIQUERY})?)?",
    "MONTH": (
        r"\b(?:[Jj]an(?:uary|uar)?|[Ff]eb(?:ruary|ruar)?|[Mm](?:a|ä)?r(?:ch|z)?|[Aa]pr(?:il)?|[Mm]a(?:y|i)?"
        r"|[Jj]un(?:e|i)?|[Jj]ul(?:y|i)?|[Aa]ug(?:ust)?|[Ss]ep(?:tember)?|[Oo](?:c|k)?t(?:ober)?"
        r"|[Nn]ov(?:ember)?|[Dd]e(?:c|z)(?:ember)?)\b"
    ),
    "MONTHNUM": r"(?:0?[1-9]|1[0-2])",
    "MONTHNUM2": r"(?:0[1-9]|1[0-2])",
    "MONTHDAY": r"(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])",
    "DAY": r"(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)",
    "YEAR": r"(?>\d\d){1,2}",
    "HOUR": r"(?:2[0123]|[01]?[0-9])",
    "MINUTE": r"(?:[0-5][0-9])",
    "SECOND": r"(?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)",
    "TIME": r"(?<![0-9])%{HOUR}:%{MINUTE}(?::%{SECOND})(?![0-9])",
    "DATE_US": r"%{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}",
    "DATE_EU": r"%{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}",
    "ISO8601_TIMEZONE": r"(?:Z|[+-]%{HOUR}(?::?%{MINUTE}))",
    "ISO8601_SECOND": r"%{SECOND}",
    "TIMESTAMP_ISO8601": r"%{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?",
    "DATE": r"%{DATE_US}|%{DATE_EU}",
    "DATESTAMP": r"%{DATE}[- ]%{TIME}",
    "TZ": r"(?:[APMCE][SD]T|UTC)",
    "DATESTAMP_RFC822": r"%{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}",
    "DATESTAMP_RFC2822": r"%{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}",
    "DATESTAMP_OTHER": r"%{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}",
    "DATESTAMP_EVENTLOG": r"%{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}",
    "SYSLOGTIMESTAMP": r"%{MONTH} +%{MONTHDAY} %{TIME}",
    "PROG": r"[\x21-\x5a\x5c\x5e-\x7e]+",
    "SYSLOGPROG": r"%{PROG:program}(?:\[%{POSINT:pid}\])?",
    "SYSLOGHOST": r"%{IPORHOST}",
    "SYSLOGFACILITY": r"<%{NONNEGINT:facility}.%{NONNEGINT:priority}>",
    "HTTPDATE": r"%{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}",
    "QS": r"%{QUOTEDSTRING}",
    "SYSLOGBASE": r"%{SYSLOGTIMESTAMP:timestamp} (?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource} %{SYSLOGPROG}:",
    "LOGLEVEL": (
        r"(?:[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo?(?:rmation)?|INFO?(?:RMATION)?"
        r"|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal"
        r"|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)"
    ),
    "HTTPDUSER": r"%{EMAILADDRESS}|%{USER}",
    "COMMONAPACHELOG": (
        r"%{IPORHOST:clientip} %{HTTPDUSER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "
        r"\"(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})\" "
        r"%{NUMBER:response} (?:%{NUMBER:bytes}|-)"
    ),
    "COMBINEDAPACHELOG": r"%{COMMONAPACHELOG} %{QS:referrer} %{QS:agent}",
}

# %{SYNTAXE}, %{SYNTAXE:champ}, %{SYNTAXE:champ:type}
_REFERENCE = re.compile(r"%\{(?P<syntaxe>[A-Za-z0-9_]+)(?::(?P<champ>[^:}]+))?(?::(?P<type>[A-Za-z]+))?\}")
# (?<nom>…) d'Oniguruma, pas (?<= ni (?<!
_CAPTURE_ONIGURUMA = re.compile(r"\(\?<(?![=!])(?P<nom>[^>]+)>")
_PROFONDEUR_MAX = 64
_TYPES = {"int": int, "integer": int, "float": float}


class GrokError(ValueError):
    """Motif grok invalide : syntaxe inconnue, récursion ou regex incorrecte."""


@traced
def load_patterns_dir(dossiers: list[str]) -> dict[str, str]:
    """Lit les fichiers de motifs (`NOM regex` par ligne) de `patterns_dir`.

    Les lignes vides et celles qui commencent par `#` sont ignorées ; un
    dossier ou un fichier illisible est journalisé et ignoré.
    """
    motifs: dict[str, str] = {}
    for dossier in dossiers:
        try:
            fichiers = sorted(p for p in Path(dossier).iterdir() if p.is_file())
        except OSError as exc:
            logger.warning(_("grok : patterns_dir illisible, ignoré : {} ({})"), dossier, exc)
            continue
        for fichier in fichiers:
            try:
                lignes = fichier.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning(_("grok : fichier de motifs illisible, ignoré : {} ({})"), fichier, exc)
                continue
            for ligne in lignes:
                ligne = ligne.strip()
                if not ligne or ligne.startswith("#") or " " not in ligne:
                    continue
                nom, regex = ligne.split(" ", 1)
                motifs[nom] = regex.strip()
    logger.debug("load_patterns_dir: {} motif(s)", len(motifs))
    return motifs


class GrokPattern:
    """Un motif grok compilé : regex Python et table groupe → (champ, type)."""

    @traced
    def __init__(self, motif: str, bibliotheque: dict[str, str]) -> None:
        """Développe les `%{…}` de `motif` avec `bibliotheque`, puis compile.

        Raises:
            GrokError: syntaxe inconnue, récursion trop profonde ou regex invalide.
        """
        self.motif = motif
        self._bibliotheque = bibliotheque
        self.champs: dict[str, tuple[str, str | None]] = {}
        regex = self._developper(motif, 0)
        try:
            self.regex = re.compile(regex)
        except re.error as exc:
            logger.debug("GrokPattern: regex invalide : {}", exc)
            raise GrokError(f"motif grok invalide : {motif!r} ({exc})") from exc
        logger.debug("GrokPattern: {} champ(s)", len(self.champs))

    @traced
    def _groupe(self, champ: str, type_: str | None) -> str:
        """Nom de groupe Python (`_g0`, `_g1`…) pour `champ`."""
        nom = f"_g{len(self.champs)}"
        self.champs[nom] = (champ, type_)
        return nom

    @traced
    def _developper(self, texte: str, profondeur: int) -> str:
        """Remplace récursivement les références `%{…}` et les captures Oniguruma."""
        if profondeur > _PROFONDEUR_MAX:
            raise GrokError(f"motif grok trop imbriqué (récursion ?) : {self.motif!r}")
        texte = _CAPTURE_ONIGURUMA.sub(lambda m: f"(?P<{self._groupe(m['nom'], None)}>", texte)

        @traced
        def remplacer(m: re.Match) -> str:
            syntaxe = m["syntaxe"]
            if syntaxe not in self._bibliotheque:
                raise GrokError(f"motif grok inconnu : %{{{syntaxe}}}")
            interieur = self._developper(self._bibliotheque[syntaxe], profondeur + 1)
            if m["champ"] is None:
                return f"(?:{interieur})"
            return f"(?P<{self._groupe(m['champ'], m['type'])}>{interieur})"

        return _REFERENCE.sub(remplacer, texte)

    @traced
    def captures(self, texte: str, *, garder_vides: bool) -> dict[str, Any] | None:
        """Captures de `texte` (recherche n'importe où, comme grok), ou None.

        Un même champ capturé plusieurs fois (alternatives) garde la
        première valeur non vide ; plusieurs valeurs deviennent un tableau.
        """
        m = self.regex.search(texte)
        if m is None:
            return None
        resultat: dict[str, Any] = {}
        for groupe, valeur in m.groupdict().items():
            if valeur is None or (valeur == "" and not garder_vides):
                continue
            champ, type_ = self.champs[groupe]
            valeur_typee = _convertir(valeur, type_)
            if champ in resultat:
                existant = resultat[champ]
                resultat[champ] = [*existant, valeur_typee] if isinstance(existant, list) else [existant, valeur_typee]
            else:
                resultat[champ] = valeur_typee
        return resultat


@traced
def _convertir(valeur: str, type_: str | None) -> Any:
    """`:int` / `:float` de grok ; une valeur non numérique reste texte."""
    conversion = _TYPES.get(type_ or "")
    if conversion is None:
        return valeur
    try:
        return conversion(valeur) if conversion is float else int(float(valeur))
    except ValueError:
        logger.debug("grok : conversion {} impossible, valeur gardée : {!r}", type_, valeur)
        return valeur


class GrokFilter:
    """`grok { match => … }` appliqué à un document (voir la docstring du module)."""

    @traced
    def __init__(self, options: dict[str, Any]) -> None:
        """Compile les motifs de `match` (un motif invalide est journalisé et ignoré)."""
        self._options = options
        bibliotheque = dict(BASE_PATTERNS)
        dossiers = options.get("patterns_dir")
        if isinstance(dossiers, str):
            dossiers = [dossiers]
        if isinstance(dossiers, list):
            bibliotheque.update(load_patterns_dir([d for d in dossiers if isinstance(d, str)]))
        definitions = options.get("pattern_definitions")
        if isinstance(definitions, dict):
            bibliotheque.update({str(k): str(v) for k, v in definitions.items()})
        self.regles: list[tuple[str, GrokPattern]] = []
        for champ, motif in _paires_match(options.get("match")):
            try:
                self.regles.append((champ, GrokPattern(motif, bibliotheque)))
            except GrokError as exc:
                logger.warning(_("grok : motif ignoré : {}"), exc)
        overwrite = options.get("overwrite", [])
        self._overwrite = set(overwrite if isinstance(overwrite, list) else [overwrite])
        self._break = options.get("break_on_match", True) is not False
        self._vides = options.get("keep_empty_captures", False) is True
        target = options.get("target")
        self._target = parse_field_path(target) if isinstance(target, str) and target else []
        logger.debug("GrokFilter: {} règle(s)", len(self.regles))

    @traced
    def apply(self, doc: dict[str, Any]) -> bool:
        """Applique les motifs ; True si au moins un a correspondu, sinon `tag_on_failure`."""
        trouve = False
        for champ, motif in self.regles:
            valeur = resolve_field(doc, parse_field_path(champ))
            if valeur is _MISSING or valeur is None:
                continue
            textes = valeur if isinstance(valeur, list) else [valeur]
            for texte in textes:
                captures = motif.captures(str(texte), garder_vides=self._vides)
                if captures is None:
                    continue
                trouve = True
                self._ecrire(doc, captures)
                if self._break:
                    break
            if trouve and self._break:
                break
        if not trouve:
            add_failure_tags(doc, self._options.get("tag_on_failure", ["_grokparsefailure"]))
        logger.debug("GrokFilter.apply: trouve={}", trouve)
        return trouve

    @traced
    def _ecrire(self, doc: dict[str, Any], captures: dict[str, Any]) -> None:
        """Écrit les captures (sous `target` éventuel), en respectant `overwrite`."""
        for champ, valeur in captures.items():
            chemin = [*self._target, *parse_field_path(champ)]
            existant = resolve_field(doc, chemin)
            if existant is _MISSING or existant is None or champ in self._overwrite:
                assign_field(doc, chemin, valeur)
            elif isinstance(existant, list):
                existant.append(valeur)
            else:
                assign_field(doc, chemin, [existant, valeur])


@traced
def _paires_match(match: Any) -> list[tuple[str, str]]:
    """`match` en liste (champ, motif) : forme hash ou ancienne forme tableau."""
    paires: list[tuple[str, str]] = []
    if isinstance(match, dict):
        for champ, motifs in match.items():
            for motif in motifs if isinstance(motifs, list) else [motifs]:
                if isinstance(motif, str):
                    paires.append((str(champ), motif))
    elif isinstance(match, list) and len(match) >= 2 and len(match) % 2 == 0:
        for i in range(0, len(match), 2):
            if isinstance(match[i], str) and isinstance(match[i + 1], str):
                paires.append((match[i], match[i + 1]))
    else:
        logger.debug("grok : match mal formé, ignoré : {!r}", match)
    return paires
