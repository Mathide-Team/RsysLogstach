#!/usr/bin/env python3
"""Point d'entrée rsyslog `omprog` : stdin JSON → filtres → enrichissement → pipeline → OpenSearch.

Reconstruit (issue #40) : le fichier d'origine n'a pas été retrouvé. Le
comportement suit le README, FEATURES.md, CLAUDE.md et les contrats que les
modules d'origine décrivent pour leur appelant (« `src/omprog` » dans leurs
docstrings).

Protocole omprog (rsyslog, `confirmMessages="on"`) :

- une ligne par message sur stdin (template JSON côté rsyslog) ;
- le programme écrit « OK » sur stdout quand il est prêt, puis une ligne
  par message traité : « OK » si le message est traité (indexé, abandonné
  par un filtre, mis en DLQ), autre chose sinon. rsyslog suspend alors
  l'action et renvoie le message plus tard (échec transitoire) ;
- stdout est réservé au protocole : les journaux (loguru) vont sur stderr ;
- fin de stdin (arrêt de rsyslog) ou SIGTERM : arrêt propre, ressources fermées.

Ordre de traitement d'un message, fidèle au schéma du README :
`--filters` (FilterPipeline) → `--enrich-dict` / `--geoip-db` (enrichment)
→ `--pipeline-conf` (PipelineInterpreter) → OpenSearchIndexer.

Secrets : `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD` en environnement
uniquement (`util.opensearch_auth_from_env`), jamais en option de ligne de
commande (visible par `ps aux`).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from loguru import logger

from dlq import LocalDeadLetterQueue, parse_duration, parse_size
from enrichment import DictEnricher, GeoIPEnricher
from filters import FilterPipeline
from indexer import OpenSearchIndexer, SendOutcome
from interpreter import PipelineInterpreter
from tracing import traced
from util import load_json_file, opensearch_auth_from_env

ACK_OK = "OK"
# Toute réponse autre que « OK » est un échec pour rsyslog : il suspend
# l'action puis renvoie le message. Le texte est journalisé par rsyslog.
ACK_RETRY = "Erreur : indexation OpenSearch temporairement impossible, message à renvoyer"

# Plugins `output {}` d'un pipeline `.conf` que ce pont sait honorer.
_INDEX_PLUGINS = frozenset({"opensearch", "elasticsearch"})

DEFAULT_INDEX_PATTERN = "switch-logs-%Y.%m.%d"
DEFAULT_INDEX_TEMPLATE_NAME = "switch-logs"


# ----------------------------------------------------------------------
# Ligne de commande
# ----------------------------------------------------------------------


@traced
def build_parser() -> argparse.ArgumentParser:
    """Options de la ligne de commande (README, section « Utilisation »)."""
    parser = argparse.ArgumentParser(
        prog="omprog.py",
        description="Pont rsyslog omprog -> OpenSearch, compatible schéma/filtres Logstash.",
    )
    g = parser.add_argument_group("filtres et pipeline")
    g.add_argument("--filters", metavar="JSON", help="Chaîne de filtres (format filters.example.json)")
    g.add_argument(
        "--filters-on-missing",
        choices=("keep", "empty"),
        default="keep",
        help="Rendu d'un %%{champ} absent dans les filtres (défaut : keep)",
    )
    g.add_argument(
        "--pipeline-conf",
        metavar="CHEMIN",
        help="Pipeline Logstash : un fichier .conf, ou un dossier dont les *.conf sont lus par ordre de nom",
    )
    g.add_argument(
        "--pipeline-on-missing",
        choices=("keep", "empty"),
        default="keep",
        help="Rendu d'un %%{champ} absent dans le pipeline (défaut : keep)",
    )

    g = parser.add_argument_group("enrichissement")
    g.add_argument("--enrich-dict", metavar="JSON", help="Dictionnaire statique (format enrich-dict.example.json)")
    g.add_argument("--enrich-key-field", default="hostname", help="Champ clé du dictionnaire (défaut : hostname)")
    g.add_argument("--enrich-out-field", default="enrichment", help="Champ de sortie (défaut : enrichment)")
    g.add_argument("--geoip-db", metavar="MMDB", help="Base MaxMind GeoIP2 City (.mmdb)")
    g.add_argument("--geoip-ip-field", default="fromhost-ip", help="Champ contenant l'IP (défaut : fromhost-ip)")
    g.add_argument("--geoip-out-field", default="geoip", help="Champ de sortie (défaut : geoip)")

    g = parser.add_argument_group("OpenSearch")
    g.add_argument(
        "--opensearch-host",
        action="append",
        metavar="URL",
        help="Nœud OpenSearch, ex. https://localhost:9200 (option répétable ; défaut : https://localhost:9200)",
    )
    g.add_argument("--no-verify-certs", action="store_true", help="Ne pas vérifier les certificats TLS")
    g.add_argument(
        "--index-pattern",
        default=DEFAULT_INDEX_PATTERN,
        help="Motif strftime de l'index quotidien (défaut : " + DEFAULT_INDEX_PATTERN.replace("%", "%%") + ")",
    )
    g.add_argument("--index-template", metavar="JSON", help="Index template à installer au démarrage")
    g.add_argument(
        "--index-template-name",
        default=DEFAULT_INDEX_TEMPLATE_NAME,
        help=f"Nom de l'index template (défaut : {DEFAULT_INDEX_TEMPLATE_NAME})",
    )
    g.add_argument("--document-id-template", metavar="GABARIT", help="_id déterministe, ex. %%{[event_id]}")
    g.add_argument(
        "--document-id-fingerprint",
        metavar="CHAMPS",
        help="_id par empreinte : champs séparés par des virgules, ou « * » pour le document entier",
    )
    g.add_argument("--fingerprint-method", choices=("sha256", "sha1", "md5"), default="sha256")

    g = parser.add_argument_group("dead letter queue (issue #27)")
    g.add_argument("--dlq-path", metavar="JSONL", help="Fichier DLQ des échecs permanents")
    g.add_argument("--dlq-max-size", type=parse_size, default=0, help="Rotation au-delà de cette taille (ex. 100M)")
    g.add_argument("--dlq-max-age", type=parse_duration, default=None, help="Rotation au-delà de cet âge (ex. 7d)")
    g.add_argument("--dlq-backups", type=int, default=0, help="Fichiers rotatés conservés au maximum")
    g.add_argument("--dlq-retention", type=parse_duration, default=None, help="Âge maximal d'un fichier rotaté")
    g.add_argument("--dlq-no-compress", action="store_true", help="Ne pas compresser les fichiers rotatés")

    parser.add_argument(
        "--log-level", default="INFO", choices=("TRACE", "DEBUG", "INFO", "WARNING", "ERROR"), help="Niveau sur stderr"
    )
    return parser


@traced
def parse_hosts(urls: list[str] | None) -> tuple[list[dict[str, str | int]], bool]:
    """URLs `--opensearch-host` -> (nœuds pour opensearch-py, use_ssl).

    Raises:
        ValueError: URL sans hôte, ou mélange http/https.
    """
    hosts: list[dict[str, str | int]] = []
    schemes: set[str] = set()
    for url in urls or ["https://localhost:9200"]:
        parts = urlsplit(url if "://" in url else f"https://{url}")
        if not parts.hostname:
            raise ValueError(f"--opensearch-host invalide : {url!r}")
        schemes.add(parts.scheme)
        hosts.append({"host": parts.hostname, "port": parts.port or 9200})
    if len(schemes) > 1:
        raise ValueError("--opensearch-host : tous les nœuds doivent utiliser le même schéma (http ou https)")
    return hosts, schemes == {"https"}


@traced
def read_pipeline_source(path: str) -> str:
    """Texte du pipeline : un fichier, ou les *.conf d'un dossier concaténés par ordre de nom (comme Logstash)."""
    p = Path(path)
    if p.is_dir():
        files = sorted(f for f in p.iterdir() if f.is_file() and f.suffix == ".conf")
        if not files:
            raise ValueError(f"--pipeline-conf : aucun fichier .conf dans {path}")
        return "\n".join(f.read_text(encoding="utf-8") for f in files)
    return p.read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Traitement d'un message
# ----------------------------------------------------------------------


@dataclass
class Bridge:
    """Chaîne de traitement d'un message, indépendante de stdin/stdout (testable)."""

    indexer: Any
    filters: FilterPipeline | None = None
    filters_on_missing: str = "keep"
    enrichers: list[Any] = field(default_factory=list)
    interpreter: PipelineInterpreter | None = None
    pipeline_on_missing: str = "keep"
    dlq: LocalDeadLetterQueue | None = None

    @traced
    async def handle_line(self, line: str) -> str:
        """Traite une ligne reçue de rsyslog et renvoie la réponse omprog (« OK » ou un message d'échec)."""
        line = line.strip()
        if not line:
            return ACK_OK
        try:
            doc = json.loads(line)
        except json.JSONDecodeError as exc:
            # Message illisible : le renvoyer ne le rendra pas lisible. On le
            # garde en DLQ s'il y en a une, puis on confirme pour ne pas boucler.
            logger.warning("Message JSON invalide ignoré erreur={error}", error=exc)
            await self._dead_letter({"message": line}, error=f"JSON invalide : {exc}")
            return ACK_OK
        if not isinstance(doc, dict):
            logger.warning("Message JSON qui n'est pas un objet, ignoré")
            await self._dead_letter({"message": line}, error="JSON qui n'est pas un objet")
            return ACK_OK
        outcome = await self.handle_doc(doc)
        return ACK_RETRY if outcome is SendOutcome.RETRYABLE else ACK_OK

    @traced
    async def handle_doc(self, doc: dict[str, Any]) -> SendOutcome | None:
        """Filtres, enrichissement, pipeline, indexation. `None` : document abandonné (drop) ou sans sortie."""
        if self.filters is not None and not self.filters.apply(doc, on_missing=self.filters_on_missing):
            return None
        for enricher in self.enrichers:
            enricher.enrich(doc)
        if self.interpreter is None:
            return await self.indexer.send(doc)
        actions = self.interpreter.apply(doc, on_missing=self.pipeline_on_missing)
        if actions is None:
            return None
        if not self.interpreter.has_output:
            # Pipeline réduit à filter{} : destination statique de la ligne de commande.
            return await self.indexer.send(doc)
        outcome: SendOutcome | None = None
        for action in actions:
            if action.plugin not in _INDEX_PLUGINS:
                logger.debug("Sortie {plugin} non gérée par omprog, ignorée", plugin=action.plugin)
                continue
            result = await self.indexer.send(
                doc,
                index=_option_str(action.options.get("index")),
                document_id=_option_str(action.options.get("document_id")),
            )
            # Un seul échec transitoire suffit pour que rsyslog renvoie le message.
            if result is SendOutcome.RETRYABLE or outcome is None:
                outcome = result
        return outcome

    @traced
    async def _dead_letter(self, doc: dict[str, Any], *, error: str) -> None:
        """Écrit un message inexploitable dans la DLQ, si elle est configurée."""
        if self.dlq is not None:
            await self.dlq.write(doc, index="", error=error)

    @traced
    async def close(self) -> None:
        """Ferme l'indexeur et les bases ouvertes (mmdb/geoip)."""
        if self.interpreter is not None:
            self.interpreter.close()
        if self.filters is not None:
            self.filters.close()
        for enricher in self.enrichers:
            close = getattr(enricher, "close", None)
            if close is not None:
                close()
        await self.indexer.close()


@traced
def _option_str(value: Any) -> str | None:
    """Option d'`output{}` rendue -> chaîne non vide, ou None."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


# ----------------------------------------------------------------------
# Construction à partir des options
# ----------------------------------------------------------------------


@traced
def build_bridge(args: argparse.Namespace, *, indexer_factory: Callable[..., Any] = OpenSearchIndexer) -> Bridge:
    """Compile filtres, enrichissement et pipeline ; prépare l'indexeur et la DLQ.

    Toute erreur de configuration lève une exception au démarrage (échec franc
    voulu, voir interpreter.py), avant le « OK » initial à rsyslog.
    """
    dlq = None
    if args.dlq_path:
        dlq = LocalDeadLetterQueue(
            args.dlq_path,
            max_bytes=args.dlq_max_size,
            max_age=args.dlq_max_age,
            backups=args.dlq_backups,
            retention=args.dlq_retention,
            compress=not args.dlq_no_compress,
        )
    filters = FilterPipeline(load_json_file(args.filters)) if args.filters else None
    enrichers: list[Any] = []
    if args.enrich_dict:
        enrichers.append(DictEnricher(load_json_file(args.enrich_dict), args.enrich_key_field, args.enrich_out_field))
    if args.geoip_db:
        enrichers.append(GeoIPEnricher(args.geoip_db, args.geoip_ip_field, args.geoip_out_field))
    interpreter = PipelineInterpreter(read_pipeline_source(args.pipeline_conf)) if args.pipeline_conf else None

    fingerprint_fields: list[str] | None = None
    if args.document_id_fingerprint is not None:
        raw = args.document_id_fingerprint.strip()
        fingerprint_fields = [] if raw in ("", "*") else [f.strip() for f in raw.split(",") if f.strip()]
    hosts, use_ssl = parse_hosts(args.opensearch_host)
    indexer = indexer_factory(
        hosts=hosts,
        auth=opensearch_auth_from_env(),
        index_pattern=args.index_pattern,
        use_ssl=use_ssl,
        verify_certs=not args.no_verify_certs,
        document_id_template=args.document_id_template,
        dlq=dlq,
        document_id_fingerprint_fields=fingerprint_fields,
        document_id_fingerprint_method=args.fingerprint_method,
    )
    return Bridge(
        indexer=indexer,
        filters=filters,
        filters_on_missing=args.filters_on_missing,
        enrichers=enrichers,
        interpreter=interpreter,
        pipeline_on_missing=args.pipeline_on_missing,
        dlq=dlq,
    )


@traced
async def install_index_template(client: Any, name: str, path: str) -> None:
    """Installe l'index template (composable si `index_patterns` + `template`, sinon ancien format)."""
    body = load_json_file(path)
    if "template" in body:
        await client.indices.put_index_template(name=name, body=body)
    else:
        await client.indices.put_template(name=name, body=body)
    logger.info("Index template installé nom={name}", name=name)


# ----------------------------------------------------------------------
# Boucle omprog
# ----------------------------------------------------------------------


@traced
async def serve(
    bridge: Bridge,
    readline: Callable[[], Awaitable[bytes]],
    write: Callable[[str], None],
    stop: asyncio.Event | None = None,
) -> int:
    """Boucle principale : « OK » initial, puis une réponse par ligne jusqu'à EOF ou `stop`.

    Returns:
        Nombre de lignes traitées.
    """
    stop = stop or asyncio.Event()
    write(ACK_OK)
    count = 0
    try:
        while not stop.is_set():
            read = asyncio.ensure_future(readline())
            stopped = asyncio.ensure_future(stop.wait())
            done, _ = await asyncio.wait({read, stopped}, return_when=asyncio.FIRST_COMPLETED)
            if read not in done:
                read.cancel()
                break
            stopped.cancel()
            raw = read.result()
            if not raw:
                break  # EOF : rsyslog ferme stdin à l'arrêt
            try:
                reply = await bridge.handle_line(raw.decode("utf-8", errors="replace"))
            except Exception as exc:  # noqa: BLE001 - un message ne doit pas arrêter le pont
                logger.exception("Échec inattendu du traitement d'un message erreur={error}", error=exc)
                reply = f"Erreur : {type(exc).__name__}"
            write(reply)
            count += 1
    finally:
        await bridge.close()
    return count


@traced
def _stdout_writer(reply: str) -> None:
    """Écrit une réponse omprog sur stdout et vide le tampon (rsyslog attend chaque ligne)."""
    sys.stdout.write(reply.replace("\n", " ") + "\n")
    sys.stdout.flush()


@traced
async def _stdin_reader() -> Callable[[], Awaitable[bytes]]:
    """Lecteur asynchrone de stdin (pipe ouvert par rsyslog)."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=2**24)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    return reader.readline


@traced
async def amain(args: argparse.Namespace) -> int:
    """Construit le pont, installe l'index template, sert jusqu'à l'arrêt."""
    bridge = build_bridge(args)
    if args.index_template:
        await install_index_template(bridge.indexer._client, args.index_template_name, args.index_template)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    count = await serve(bridge, await _stdin_reader(), _stdout_writer, stop)
    logger.info("Arrêt du pont messages={count}", count=count)
    return 0


@traced
def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : options, journaux sur stderr, boucle asyncio."""
    args = build_parser().parse_args(argv)
    logger.remove()
    logger.add(sys.stderr, level=args.log_level)
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
