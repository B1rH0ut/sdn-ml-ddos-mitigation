.PHONY: help setup download-data train train-real train-all evaluate \
       test test-unit test-adversarial lint run run-topo \
       docker-build docker-up docker-down clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

setup: ## Install package in editable mode with dev and ML extras
	pip install -e ".[dev,ml]"

download-data: ## Download real-world datasets (CIC-IDS2017, CIC-DDoS2019, UNSW-NB15)
	python -m sdn_ddos_detector.datasets.download_datasets

train: ## Train model on synthetic dataset
	python -m sdn_ddos_detector.ml.train

train-real: ## Train model on all real-world datasets
	python -m sdn_ddos_detector.ml.train --dataset all-real

train-all: ## Train on synthetic, then real-world datasets
	$(MAKE) train
	$(MAKE) train-real

evaluate: ## Evaluate trained model (ROC curves, metrics)
	python -m sdn_ddos_detector.ml.evaluation

test: ## Run full test suite
	python -m pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	python -m pytest tests/unit/ -v --tb=short

test-adversarial: ## Run adversarial robustness tests (slow)
	python -m pytest tests/adversarial/ -v --tb=short

lint: ## Run linter on source and test code
	ruff check src/ tests/

run: ## Start the Ryu SDN controller
	ryu-manager src/sdn_ddos_detector/controller/ddos_controller.py

run-topo: ## Start Mininet topology (requires root)
	sudo python -m sdn_ddos_detector.topology.topology

docker-build: ## Build Docker images
	docker compose build

docker-up: ## Start services with Docker Compose
	docker compose up -d

docker-down: ## Stop Docker Compose services
	docker compose down

clean: ## Remove build artifacts, caches, and coverage files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage
