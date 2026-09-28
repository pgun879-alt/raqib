.DEFAULT_GOAL := help
PYTHON := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: help setup test lint typecheck check demo check-targets watch serve-demo report clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## Create the virtual environment and install the package with dev extras
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[dev]'
	@test -f targets.yaml || cp targets.example.yaml targets.yaml
	@echo "targets.yaml ready -- edit it to add your own targets"

test: ## Run the test suite
	$(PYTHON) -m pytest

lint: ## Check formatting and lint rules
	.venv/bin/ruff format --check .
	.venv/bin/ruff check .

typecheck: ## Run mypy
	.venv/bin/mypy

check: lint typecheck test ## Run every check the CI would run

demo: ## Full offline demo: robots, false-positive suppression, change, outage, recovery
	./scripts/demo.sh

check-targets: ## Check every target once
	$(PYTHON) -m raqib.cli check

validate: ## Validate targets.yaml and run every URL past the SSRF guard without fetching
	$(PYTHON) -m raqib.cli validate

watch: ## Run continuously on each target's own interval
	$(PYTHON) -m raqib.cli watch

report: ## Check every target and write HTML + Markdown reports
	$(PYTHON) -m raqib.cli report

serve-demo: ## Serve the bundled demo site on 127.0.0.1:8999
	$(PYTHON) -m raqib.cli serve-demo

clean: ## Remove caches and demo artefacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -f data/demo.sqlite3 data/demo.sqlite3-wal data/demo.sqlite3-shm data/demo-alerts.jsonl
	rm -f reports/demo.html reports/demo.md
