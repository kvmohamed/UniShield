# ============================================================
# UniShield — Makefile
# ============================================================

.PHONY: help install dev test lint run dashboard docker-build docker-up docker-down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip install -r requirements.txt
	pip install -e .

dev: ## Install with dev dependencies
	pip install -r requirements.txt
	pip install -e ".[dev]"

test: ## Run all tests
	pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	pytest tests/unit/ -v --tb=short

test-integration: ## Run integration tests
	pytest tests/integration/ -v --tb=short

test-performance: ## Run performance tests
	pytest tests/performance/ -v --tb=short -m performance

test-cov: ## Run tests with coverage
	pytest tests/ -v --cov=src/unishield --cov-report=html --cov-report=term-missing

lint: ## Run linter
	ruff check src/ tests/
	ruff format --check src/ tests/

format: ## Format code
	ruff format src/ tests/

run: ## Start the API server
	python -m unishield.main

dashboard: ## Start the Streamlit dashboard
	streamlit run src/unishield/dashboard/streamlit_app.py --server.port 8501

docker-build: ## Build Docker images
	docker-compose build

docker-up: ## Start Docker containers
	docker-compose up -d

docker-down: ## Stop Docker containers
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f

clean: ## Clean build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name *.egg-info -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ .coverage .ruff_cache/
