"""Indexation OpenSearch, un index par jour, avec document_id optionnel façon gabarit Logstash.

Extrait d'omprog.py (session 9, réorganisation selon le squelette de
Mathilde). Dépend de `tracing`, de `templates` (pour le document_id
dynamique, session 9) et de `dlq` (dead letter queue locale pour les
échecs permanents, session 13 — voir plus bas) ; jamais de `filters` ni
`enrichment` (aucune raison pour l'indexation de connaître les filtres
d'extraction ou l'enrichissement).

Fix de cohérence (session 13, constaté en touchant ce fichier pour la DLQ) :
`@traced` (voir PATTERNS.md, "Traçabilité systématique des fonctions")
n'était appliqué à AUCUNE fonction de ce module jusqu'ici, contrairement à
la convention "toutes les fonctions du projet" en place depuis la session
9 — un oubli de la réorganisation de cette session-là, pas une exception
volontaire. Ajouté ci-dessous à toutes les méthodes.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from loguru import logger
from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError, OpenSearchException, RequestError

from dlq import LocalDeadLetterQueue
from fingerprint import compute_fingerprint
from templates import CompiledTemplate, compile_template, render
from tracing import traced

OPENSEARCH_TIMEOUT = 3.0  # secondes, timeout socket du client OpenSearch

# Erreurs considérées comme permanentes (jamais transitoires) : un document
# qui provoque l'une d'elles ne deviendra jamais indexable en le rejouant
# tel quel (RequestError = 400, ex. type de champ incompatible avec le
# mapping de l'index ; NotFoundError = 404). Toute autre OpenSearchException
# (ConnectionError, ConnectionTimeout, erreur 5xx...) reste traitée comme
# transitoire, comportement inchangé.
_PERMANENT_ERRORS = (RequestError, NotFoundError)


class SendOutcome(enum.Enum):
    """Résultat d'`OpenSearchIndexer.send`, distingue trois issues (session 13).

    - INDEXED : le document a été indexé avec succès.
    - RETRYABLE : échec transitoire — comportement historique (avant la
      session 13, seul un booléen existait) : rendre le message à rsyslog
      pour qu'il le retienne et le renvoie plus tard.
    - DEAD_LETTERED : échec permanent, écrit dans la DLQ locale si
      `dlq` est configuré (voir `dlq.py`) — décision de routage
      définitive, comme un `DropFilter` (`filters.py`) : ne JAMAIS
      retenter, mais confirmer "OK" à rsyslog pour ne pas boucler
      indéfiniment (voir FEATURES.md, item "Proposé" #2 avant cette
      session). Si `dlq` n'est PAS configuré, ce cas n'est jamais produit :
      `send` retombe alors sur RETRYABLE pour rester rétrocompatible avec
      le comportement d'avant cette session.
    """

    INDEXED = "indexed"
    RETRYABLE = "retryable"
    DEAD_LETTERED = "dead_lettered"


class OpenSearchIndexer:
    """Indexation asynchrone des documents dans OpenSearch, un index par jour.

    document_id : si `document_id_template` est fourni, un gabarit façon
    Logstash (`templates.py`, ex. "%{[event_id]}" ou
    "%{host}-%{+YYYY.MM.dd}") est rendu contre chaque document pour
    produire un `_id` déterministe — même usage que `document_id =>
    "%{event_id}"` dans un output elasticsearch/opensearch de Logstash
    (voir le document de référence, section 5, "Identifiant de document
    dynamique"). Sans ce gabarit, OpenSearch génère un `_id` aléatoire
    comme avant cette session (comportement par défaut inchangé). Un
    gabarit qui rend une chaîne vide (tous ses champs référencés absents)
    revient au comportement par défaut pour CE document plutôt que
    d'indexer avec un `_id` vide.

    dlq (session 13) : si fourni, un échec d'indexation identifié comme
    PERMANENT (voir `_PERMANENT_ERRORS`) est écrit dans cette dead letter
    queue locale plutôt que rendu indéfiniment à rsyslog — voir `dlq.py`
    et `SendOutcome`. Sans `dlq` (défaut), comportement historique
    inchangé : toute `OpenSearchException`, permanente ou non, retombe sur
    `SendOutcome.RETRYABLE`.

    document_id_fingerprint_fields (session 17, `fingerprint.py`) : si
    fourni (même une liste vide), un `_id` déterministe est dérivé d'un
    HASH du contenu (voir `fingerprint.compute_fingerprint`) plutôt que du
    gabarit `document_id_template` — répond à l'item "Proposé" #4 de
    FEATURES.md, pour les documents sans champ identifiant naturel. `None`
    (défaut) désactive ce mécanisme et laisse `document_id_template` seul
    décider, comportement historique inchangé. Les deux options ne sont
    PAS combinées : si `document_id_fingerprint_fields` est fourni, il a
    priorité sur `document_id_template` pour CE document (voir
    `_document_id`) — cohérent avec le fait qu'un fingerprint EST déjà un
    identifiant déterministe, inutile de le combiner à un gabarit.
    """

    @traced
    def __init__(
        self,
        hosts: list[dict[str, str | int]],
        auth: tuple[str, str] | None,
        index_pattern: str,
        use_ssl: bool,
        verify_certs: bool,
        document_id_template: str | None = None,
        dlq: LocalDeadLetterQueue | None = None,
        document_id_fingerprint_fields: list[str] | None = None,
        document_id_fingerprint_method: str = "sha256",
    ) -> None:
        """Initialise le client OpenSearch.

        Args:
            hosts: Liste de nœuds, ex. [{"host": "127.0.0.1", "port": 9200}].
            auth: Couple (utilisateur, mot de passe), ou None si non authentifié.
            index_pattern: Motif strftime du nom d'index quotidien (ex.
                "switch-logs-%Y.%m.%d").
            use_ssl: Utiliser HTTPS pour se connecter aux nœuds.
            verify_certs: Vérifier les certificats TLS (à désactiver
                seulement pour un cluster interne à certificat auto-signé).
            document_id_template: Gabarit Logstash optionnel (voir la
                docstring de la classe) pour un `_id` déterministe.
            dlq: Dead letter queue locale optionnelle (session 13, voir la
                docstring de la classe) pour les échecs permanents.
            document_id_fingerprint_fields: Liste de chemins de champs
                (session 17, voir la docstring de la classe) pour un `_id`
                dérivé d'un hash du contenu, au lieu de
                `document_id_template`. `None` (défaut) désactive ce
                mécanisme ; une liste VIDE empreint le document entier
                (voir `fingerprint.compute_fingerprint`).
            document_id_fingerprint_method: Algorithme de hachage
                (`sha256` par défaut, voir `fingerprint.py`).
        """
        self._index_pattern = index_pattern
        self._document_id_template: CompiledTemplate | None = (
            compile_template(document_id_template) if document_id_template else None
        )
        self._document_id_fingerprint_fields = document_id_fingerprint_fields
        self._document_id_fingerprint_method = document_id_fingerprint_method
        self._dlq = dlq
        self._client = AsyncOpenSearch(
            hosts=hosts,
            http_auth=auth,
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            ssl_show_warn=False,
            timeout=OPENSEARCH_TIMEOUT,
        )

    @traced
    def _current_index(self) -> str:
        """Calcule le nom de l'index du jour à partir du motif configuré."""
        return datetime.now(timezone.utc).strftime(self._index_pattern)

    @traced
    def _document_id(self, doc: dict) -> str | None:
        """Calcule l'`_id` statique de `doc` : fingerprint si configuré, sinon gabarit, sinon None.

        Priorité (session 17) : `document_id_fingerprint_fields` d'abord
        (si non `None`, même une liste vide), sinon `document_id_template`
        — les deux ne sont jamais combinés, voir la docstring de la
        classe. Ni l'un ni l'autre configuré, ou empreinte/gabarit rendu
        vide pour CE document : `None` (retombe sur un `_id` aléatoire).
        """
        if self._document_id_fingerprint_fields is not None:
            return compute_fingerprint(doc, self._document_id_fingerprint_fields, self._document_id_fingerprint_method)
        if self._document_id_template is None:
            return None
        rendered = render(self._document_id_template, doc, on_missing="empty")
        return rendered or None

    @traced
    async def send(self, doc: dict, *, index: str | None = None, document_id: str | None = None) -> SendOutcome:
        """Indexe un document dans OpenSearch.

        Args:
            doc: Document déjà enrichi, prêt à indexer.
            index: Nom d'index à utiliser pour CE document, au lieu du
                motif quotidien statique (`index_pattern`) — surcharge
                ponctuelle (session 12) produite par exemple par un output
                `elasticsearch`/`opensearch` d'un pipeline `.conf`
                interprété (`interpreter.PipelineInterpreter`). `None`
                (par défaut) conserve le comportement historique.
            document_id: `_id` à utiliser pour CE document, au lieu du
                gabarit statique (`document_id_template`) — même logique
                de surcharge ponctuelle. Une chaîne vide est traitée comme
                `None` (retombe sur `document_id_template`/`_id`
                aléatoire), même convention que `_document_id` pour un
                gabarit qui rend une chaîne vide.

        Returns:
            `SendOutcome` (session 13, voir sa docstring) : `INDEXED` si
            l'indexation a réussi, `DEAD_LETTERED` si l'échec est permanent
            ET qu'une `dlq` est configurée, `RETRYABLE` sinon (échec
            transitoire, ou permanent sans `dlq` configurée — comportement
            historique).
        """
        resolved_index = index or self._current_index()
        resolved_id = document_id or self._document_id(doc)
        try:
            await self._client.index(index=resolved_index, body=doc, id=resolved_id)
            return SendOutcome.INDEXED
        except _PERMANENT_ERRORS as exc:
            logger.warning("Indexation OpenSearch échouée définitivement erreur={error}", error=exc)
            if self._dlq is not None:
                await self._dlq.write(doc, index=resolved_index, error=str(exc))
                return SendOutcome.DEAD_LETTERED
            return SendOutcome.RETRYABLE
        except OpenSearchException as exc:
            logger.warning("Indexation OpenSearch échouée erreur={error}", error=exc)
            return SendOutcome.RETRYABLE

    @traced
    async def close(self) -> None:
        """Ferme proprement le client OpenSearch."""
        await self._client.close()
