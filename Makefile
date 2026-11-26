.PHONY: setup test security up-idp down-idp verify-idp up clean

UV := $(HOME)/.local/bin/uv
PYTHON := .venv/bin/python

setup:
	$(UV) venv --python 3.12
	$(UV) pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -v

security:
	$(PYTHON) -m ruff check src tests scripts --select E9,F63,F7,F82
	$(PYTHON) -m bandit -r src scripts --severity-level high

up-idp:
	docker compose up -d

down-idp:
	docker compose down -v

verify-idp:
	$(PYTHON) scripts/verify_live_keycloak.py

up:
	$(PYTHON) -m uvicorn limen.web:app --host 127.0.0.1 --port 8004

clean:
	rm -rf data/*.db .pytest_cache
