.PHONY: help install lint test cov security run seed clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

install: ## Create a virtualenv and install the package with dev extras
	python3 -m venv .venv && . .venv/bin/activate && pip install -U pip && pip install -e ".[dev]"

lint: ## Static analysis
	ruff check .

test: ## Unit tests
	pytest

cov: ## Tests with coverage report
	pytest --cov=fasoshield --cov-report=term-missing

security: ## SAST and dependency audit
	bandit -q -r src -c pyproject.toml
	pip-audit

run: ## Run the API locally (reload)
	uvicorn fasoshield.api.main:app --reload

seed: ## Import the seed signature files into the local database
	fasoshield db import signatures/hashes/blocklist.seed.csv
	fasoshield db import-official signatures/hashes/official_apps.seed.csv

clean: ## Remove local build and cache artifacts
	rm -rf .venv .pytest_cache .ruff_cache coverage.xml data
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
