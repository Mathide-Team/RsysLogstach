# SPDX-License-Identifier: GPL-3.0-or-later
# Makefile — commandes usuelles du dépôt (fin de l'issue #73).
#
# Le seuil de couverture vit uniquement dans pyproject.toml
# ([tool.coverage.report] fail_under) : ce fichier le lit pour l'afficher,
# il ne le redéclare pas — une seule source de vérité, comme le job CI
# « Qualité » (.github/workflows/ci.yml).

PYTHON ?= uv run python
PYTEST ?= uv run pytest
RUFF ?= uv run ruff

# Seuil lu depuis pyproject.toml (tomllib, Python >= 3.11 — déjà requis par le projet).
FAIL_UNDER := $(shell $(PYTHON) -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['tool']['coverage']['report']['fail_under'])" 2>/dev/null)

.PHONY: help test lint fmt fmt-fix i18n seuil

help: ## Affiche les cibles disponibles
	@echo "Commandes usuelles (mêmes commandes que la CI) :"
	@echo "  make test     pytest --cov (seuil bloquant $(FAIL_UNDER) %, lu depuis pyproject.toml)"
	@echo "  make lint     ruff check ."
	@echo "  make fmt      ruff format --check ."
	@echo "  make fmt-fix  ruff format ."
	@echo "  make i18n     scripts/i18n-update.sh (catalogues gettext)"
	@echo "  make seuil    affiche le seuil de couverture lu dans pyproject.toml"

test: ## Tests avec couverture, seuil bloquant lu dans pyproject.toml
	$(PYTEST) -q --cov --cov-report=term-missing

lint: ## Vérification statique
	$(RUFF) check .

fmt: ## Vérification du formatage
	$(RUFF) format --check .

fmt-fix: ## Formatage en place
	$(RUFF) format .

i18n: ## Mise à jour des catalogues gettext
	bash scripts/i18n-update.sh

seuil: ## Seuil de couverture (source unique : pyproject.toml)
	@echo "$(FAIL_UNDER)"
