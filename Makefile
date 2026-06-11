# Flask Security Lab - developer task runner.
#
# Assumes `make` is available (Windows: via Git Bash, choco install make, or
# WSL). Recipes use a POSIX shell and inline `VAR=value cmd` env prefixes, which
# work in Git Bash / WSL. Python is invoked as `python` (use `py -3` if needed).

PYTHON ?= python
PIP    ?= $(PYTHON) -m pip

.DEFAULT_GOAL := help
.PHONY: help install run run-naive test lint format typecheck audit \
        docker-up docker-down demo clean

help: ## Show this help.
	@echo "Flask Security Lab - available targets:"
	@echo ""
	@echo "  install     Install project + dev deps and set up pre-commit hooks"
	@echo "  run         Run the app with the Blue Team ON  (defended)"
	@echo "  run-naive   Run the app with the Blue Team OFF (naive/vulnerable)"
	@echo "  test        Run the test suite with coverage"
	@echo "  lint        Lint with ruff + black --check (no changes)"
	@echo "  format      Auto-fix with ruff --fix and format with black"
	@echo "  typecheck   Run mypy (scope set in pyproject.toml)"
	@echo "  audit       Dependency CVE scan with pip-audit (informational)"
	@echo "  docker-up   Build & start the Red/Blue demo (loopback only)"
	@echo "  docker-down Stop and remove the demo containers"
	@echo "  demo        Run the Red Team CLI against the lab"
	@echo "  clean       Remove caches and build artifacts"

install: ## Install project + dev deps and pre-commit hooks.
	$(PIP) install -e ".[dev]"
	pre-commit install

run: ## Run defended (Blue Team ON).
	BLUE_TEAM_ENABLED=true WAF_ENABLED=true RATELIMIT_ENABLED=true $(PYTHON) wsgi.py

run-naive: ## Run naive (Blue Team OFF).
	BLUE_TEAM_ENABLED=false $(PYTHON) wsgi.py

test: ## Run tests with coverage.
	$(PYTHON) -m pytest --cov --cov-report=term-missing

lint: ## Lint only (no changes).
	$(PYTHON) -m ruff check .
	$(PYTHON) -m black --check .

format: ## Auto-fix lints and format.
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m black .

typecheck: ## Static type checking.
	$(PYTHON) -m mypy

audit: ## Dependency CVE scan (informational; the lab may ship CVEs by design).
	$(PYTHON) -m pip_audit --desc || true

docker-up: ## Build & start the Red/Blue demo (published on 127.0.0.1 only).
	docker compose up --build -d
	@echo "lab-defended -> http://127.0.0.1:5000  (Blue Team ON)"
	@echo "lab-naive    -> http://127.0.0.1:5001  (Blue Team OFF)"

docker-down: ## Stop and remove the demo containers.
	docker compose down

demo: ## Run the Red Team CLI against the lab.
	# No scripts/demo present yet; drive the attacks via the Red Team CLI.
	# Point it at the naive instance to watch attacks succeed, then the
	# defended one to watch them get blocked.
	$(PYTHON) -m red_team --help

clean: ## Remove caches and build artifacts.
	$(PYTHON) -c "import shutil,glob,os; [shutil.rmtree(p, ignore_errors=True) for p in ['.pytest_cache','.mypy_cache','.ruff_cache','htmlcov','build','dist']]"
	$(PYTHON) -c "import shutil,glob; [shutil.rmtree(p, ignore_errors=True) for p in glob.glob('**/__pycache__', recursive=True)]"
	$(PYTHON) -c "import os; os.remove('.coverage') if os.path.exists('.coverage') else None"
	$(PYTHON) -c "import os; os.remove('coverage.xml') if os.path.exists('coverage.xml') else None"
