CLUSTER_NAME ?= ai-enablement-gateway
LOCAL_DIR := $(CURDIR)/.local
TF_DIR := terraform/local
CHART_DIR := deploy/helm/ai-enablement-platform

.PHONY: dev-creds build-images up down test lint smoke

dev-creds:
	uv run python scripts/generate_test_keys.py --write-bundle "$(LOCAL_DIR)"

build-images:
	docker build -f services/gateway-api/Dockerfile -t ai-gateway-api:dev .
	docker build -f services/mock-llm/Dockerfile -t ai-mock-llm:dev .

up: build-images
	@if [ ! -f "$(LOCAL_DIR)/local.tfvars.json" ]; then $(MAKE) dev-creds; fi
	terraform -chdir=$(TF_DIR) init -input=false
	terraform -chdir=$(TF_DIR) apply -auto-approve -input=false -var="cluster_name=$(CLUSTER_NAME)" -var-file="$(LOCAL_DIR)/local.tfvars.json"

down:
	@if [ -f "$(TF_DIR)/terraform.tfstate" ]; then \
		terraform -chdir=$(TF_DIR) destroy -auto-approve -input=false -var="cluster_name=$(CLUSTER_NAME)" || true; \
	fi
	kind delete cluster --name "$(CLUSTER_NAME)" || true
	rm -f "$(TF_DIR)/$(CLUSTER_NAME)-config"

test:
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run python scripts/validate_aliases.py
	helm lint $(CHART_DIR)
	terraform -chdir=$(TF_DIR) fmt -check

smoke:
	uv run python scripts/smoke_test.py
