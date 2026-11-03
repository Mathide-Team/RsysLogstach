# SPDX-License-Identifier: GPL-3.0-or-later
"""Métriques Prometheus du pont (issue #35).

Le pont tournait sans aucune métrique : impossible de suivre en production le
débit, le taux d'erreur ou la taille de la DLQ. Ce module expose, sur un
registre PROPRE à chaque `Metrics` (jamais le registre global de
`prometheus_client`, pour que plusieurs ponts, ou les tests, ne se
marchent pas dessus) :

- compteurs : `rsyslogstach_messages_received_total`,
  `rsyslogstach_messages_total{outcome=...}` (issue d'un message :
  `indexed`, `dropped`, `dead_lettered`, `retryable`) et
  `rsyslogstach_errors_total{cause=...}` (`invalid_json`, `not_an_object`,
  `exception`) ;
- histogrammes : `rsyslogstach_index_latency_seconds` (durée d'un appel
  à `indexer.send`) et `rsyslogstach_message_size_bytes` (ligne reçue de
  rsyslog, en octets UTF-8) ;
- jauges : `rsyslogstach_dlq_size_bytes` (taille du fichier DLQ courant,
  lue à chaque collecte) et `rsyslogstach_retry_pending` (échecs
  transitoires consécutifs : messages refusés à rsyslog depuis la dernière
  indexation réussie, donc en attente de renvoi).

L'endpoint HTTP `/metrics` n'est démarré que sur demande
(`--metrics-port`, voir `omprog`) : sans option, le comportement du pont
ne change pas. Dépend seulement de `tracing` (feuille du graphe).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from loguru import logger
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest, start_http_server
from pystashtemplate.tracing import traced

from i18n import _

OUTCOMES = ("indexed", "dropped", "dead_lettered", "retryable")
ERROR_CAUSES = ("invalid_json", "not_an_object", "exception")

# Bornes en secondes : une indexation locale prend quelques ms, un cluster
# lent ou un failover peut dépasser la seconde.
_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
# Bornes en octets : un message syslog tient d'ordinaire sous 1 Kio, la
# limite de lecture de stdin est de 16 Mio (`omprog._stdin_reader`).
_SIZE_BUCKETS = (128, 256, 512, 1024, 2048, 4096, 8192, 16384, 65536, 262144, 1048576)


class Metrics:
    """Ensemble des métriques d'un pont, sur son propre registre Prometheus."""

    @traced
    def __init__(self, *, dlq_path: str | None = None) -> None:
        """Crée les métriques ; `dlq_path` alimente la jauge de taille de la DLQ (0 sans DLQ)."""
        self.registry = CollectorRegistry()
        self._dlq_path = dlq_path
        self.received = Counter("rsyslogstach_messages_received", "Lignes reçues de rsyslog", registry=self.registry)
        self.outcomes = Counter(
            "rsyslogstach_messages", "Messages traités, par issue", ["outcome"], registry=self.registry
        )
        self.errors = Counter(
            "rsyslogstach_errors", "Erreurs de traitement, par cause", ["cause"], registry=self.registry
        )
        for outcome in OUTCOMES:
            self.outcomes.labels(outcome=outcome)
        for cause in ERROR_CAUSES:
            self.errors.labels(cause=cause)
        self.index_latency = Histogram(
            "rsyslogstach_index_latency_seconds",
            "Durée d'un envoi à OpenSearch",
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.message_size = Histogram(
            "rsyslogstach_message_size_bytes",
            "Taille des lignes reçues de rsyslog",
            buckets=_SIZE_BUCKETS,
            registry=self.registry,
        )
        self.dlq_size = Gauge("rsyslogstach_dlq_size_bytes", "Taille du fichier DLQ courant", registry=self.registry)
        self.dlq_size.set_function(self._dlq_size_bytes)
        self.retry_pending = Gauge(
            "rsyslogstach_retry_pending",
            "Échecs transitoires consécutifs depuis la dernière indexation réussie",
            registry=self.registry,
        )

    @traced
    def _dlq_size_bytes(self) -> float:
        """Taille du fichier DLQ courant ; 0 sans DLQ ou tant que le fichier n'existe pas."""
        if not self._dlq_path:
            return 0.0
        try:
            return float(os.path.getsize(self._dlq_path))
        except OSError as exc:
            logger.debug("taille de la DLQ illisible, 0 retenu : {}", exc)
            return 0.0

    @traced
    def message_received(self, line: str) -> None:
        """Compte une ligne reçue et observe sa taille en octets."""
        self.received.inc()
        self.message_size.observe(len(line.encode("utf-8")))

    @traced
    def outcome(self, name: str) -> None:
        """Compte l'issue d'un message (`OUTCOMES`) et tient la jauge des renvois à jour."""
        self.outcomes.labels(outcome=name).inc()
        if name == "retryable":
            self.retry_pending.inc()
        elif name == "indexed":
            self.retry_pending.set(0)

    @traced
    def error(self, cause: str) -> None:
        """Compte une erreur de traitement (`ERROR_CAUSES`)."""
        self.errors.labels(cause=cause).inc()

    @traced
    def render(self) -> bytes:
        """Exposition texte Prometheus du registre (contenu de `/metrics`)."""
        return generate_latest(self.registry)

    @traced
    def serve(
        self, port: int, addr: str = "127.0.0.1", *, server_factory: Callable[..., Any] = start_http_server
    ) -> Any:
        """Démarre l'endpoint HTTP `/metrics` (thread de `prometheus_client`) et le renvoie.

        `server_factory` est injectable pour les tests. Écoute sur la boucle
        locale par défaut : exposer les métriques au réseau est un choix
        explicite (`--metrics-addr 0.0.0.0`).
        """
        logger.info(_("Métriques Prometheus sur http://{addr}:{port}/metrics"), addr=addr, port=port)
        return server_factory(port, addr=addr, registry=self.registry)
