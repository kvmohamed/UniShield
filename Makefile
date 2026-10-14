# ============================================================
# UniShield — Makefile (POSIX shells; Windows commands are in README.md)
# ============================================================

.PHONY: help install dev test test-unit test-integration test-performance test-cov lint format run docker-build docker-up docker-down docker-logs clean

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

test-performance: ## Run performance tests
	pytest tests/performance/ -v --tb=short -m performance

test-cov: ## Run tests with coverage
	pytest tests/ -v --cov=unishield --cov-report=html --cov-report=term-missing

lint: ## Run linter
	ruff check src/ tests/
	ruff format --check src/ tests/

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
