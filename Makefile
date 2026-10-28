# ============================================================
# UniShield — Makefile (POSIX shells; Windows commands are in README.md)
# ============================================================

.PHONY: help install dev test test-unit test-integration test-performance test-security test-cov lint format run demo demo-quick benchmark verify-passive export intel-status models db-upgrade admin audit-deps sbom docker-build docker-up docker-down docker-logs clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install pinned runtime dependencies + UniShield
	pip install -r requirements.txt
	pip install --no-deps -e .

dev: ## Install pinned runtime, test and report dependencies + UniShield
	pip install -r requirements-dev.txt
	pip install --no-deps -e .

test: ## Run all tests
	pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	pytest tests/unit/ -v --tb=short

test-integration: ## Run integration tests
	pytest tests/integration/ -v --tb=short

test-performance: ## Run performance tests (excluded from the default run)
	pytest tests/performance/ -v --tb=short -m performance

test-security: ## Run security tests
	pytest tests/security/ -v --tb=short

demo: ## One-command offline demo (writes reports/)
	python scripts/run_demo.py

demo-quick: ## Shorter offline demo
	python scripts/run_demo.py --quick

benchmark: ## Throughput / latency benchmark (reports/benchmark.md)
	python scripts/benchmark_pipeline.py

verify-passive: ## Static + runtime passive-mode verification
	python scripts/verify_passive_mode.py

export: ## Export stored alerts/incidents (JSON lines, CEF, STIX 2.1) to exports/on-demand
	python scripts/export_alerts.py

intel-status: ## List imported threat-intelligence indicators per source
	python scripts/import_intel.py --status

models: ## Build dataset, train and evaluate models
	python scripts/prepare_dataset.py --synthetic --seeds 1-20
	python scripts/train_models.py
	python scripts/evaluate_models.py

db-upgrade: ## Apply pending database migrations
	unishield-admin db upgrade

admin: ## Create an administrator (prompts for name and password)
	@read -p "Administrator name: " name; unishield-admin user create "$$name" --role admin

audit-deps: ## Check the pinned requirements for known vulnerabilities (needs pip-audit)
	pip-audit --no-deps --disable-pip -r requirements.txt -r requirements-dev.txt -r requirements-ml.txt

sbom: ## CycloneDX SBOM of the runtime requirements (needs cyclonedx-bom)
	cyclonedx-py requirements requirements.txt --pyproject pyproject.toml --of JSON -o unishield-runtime.cdx.json

test-cov: ## Run tests with coverage
	pytest tests/ -v --cov=unishield --cov-report=html --cov-report=term-missing

lint: ## Run linter (CI fails on pyflakes and syntax errors)
	ruff check --select F,E9 src/ tests/ scripts/

format: ## Format code
	ruff format src/ tests/

run: ## Start the API server + dashboard (http://127.0.0.1:8000/dashboard)
	python -m unishield.main

docker-build: ## Build the Docker image
	docker compose build

docker-up: ## Start the container
	docker compose up -d

docker-down: ## Stop the container
	docker compose down

docker-logs: ## Follow container logs
	docker compose logs -f

clean: ## Clean build artifacts
	find . -type d -name __pycache__ -not -path "./.venv*" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -not -path "./.venv*" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ .coverage .ruff_cache/
