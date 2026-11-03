# SPDX-License-Identifier: GPL-3.0-or-later
"""Dead letter queue locale pour les échecs d'indexation OpenSearch permanents.

Nouveau module (session 13), réponse à l'item "Proposé" #2 de FEATURES.md :
`OpenSearchIndexer` traitait jusqu'ici tout échec (connexion refusée *ou*
erreur 4xx de mapping définitive) de la même façon — nouvelle tentative,
puis message rendu à rsyslog. Un document qui provoque une erreur de
mapping permanente (ex. un champ qui ne correspond pas au type attendu par
l'index template) ne devient jamais valide en le rejouant : le retenir
indéfiniment côté rsyslog (retenté toutes les 30 s, cf. rsyslog.conf) ne
fait que boucler pour toujours, sans jamais progresser.

Ce module fournit la voie de sortie : `LocalDeadLetterQueue.write()`
consigne le document dans un fichier JSONL local (une ligne par document,
append-only) — voir `indexer.py::OpenSearchIndexer.send`, qui l'appelle
uniquement pour les erreurs identifiées comme permanentes (statut
400/404), jamais pour une erreur de connexion ou un timeout
(transitoires, comportement de retenue inchangé).

Migration #160 : l'implémentation a été portée telle quelle dans
PyStashTemplate (`pystashtemplate.dlq`, issue #11) pour que la sortie
OpenSearch référence (`outputs/opensearch.py`) partage EXACTEMENT le même
format et le même fichier que ce connecteur — ce module n'est plus qu'un
ré-export : même classe, mêmes fonctions, aucune perte à la migration
(les tests historiques du port continuent de passer tels quels).
"""

from __future__ import annotations

from pystashtemplate.dlq import LocalDeadLetterQueue, parse_duration, parse_size

__all__ = ["LocalDeadLetterQueue", "parse_duration", "parse_size"]
