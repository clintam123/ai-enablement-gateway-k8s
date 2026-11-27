CLUSTER_NAME ?= ai-enablement-gateway
ENABLE_OBSERVABILITY ?= true
LOCAL_DIR := $(CURDIR)/.local
TF_DIR := terraform/local
GCP_TF_DIR := terraform/gcp
CHART_DIR := deploy/helm/ai-enablement-platform

GCP_PROJECT_ID ?=
GCP_REGION ?= us-central1
GCP_CLUSTER_NAME ?= ai-enablement-gateway-gcp
GCP_ARTIFACT_REPO ?= ai-enablement-gateway
GCP_IMAGE_TAG ?= dev
ENABLE_GEMINI_PROVIDER ?= false
GEMINI_API_KEY ?=

.PHONY: dev-creds build-images up down gcp-up gcp-down test lint smoke checkov trivy

dev-creds:
	uv run python scripts/generate_test_keys.py --write-bundle "$(LOCAL_DIR)"

build-images:
	docker build -f services/gateway-api/Dockerfile -t ai-gateway-api:dev .
	docker build -f services/mock-llm/Dockerfile -t ai-mock-llm:dev .
	docker build -f services/mcp-runtime/Dockerfile -t ai-mcp-runtime:dev .

up: build-images
	@if [ ! -f "$(LOCAL_DIR)/local.tfvars.json" ]; then $(MAKE) dev-creds; fi
	terraform -chdir=$(TF_DIR) init -input=false
	terraform -chdir=$(TF_DIR) apply -auto-approve -input=false -var="cluster_name=$(CLUSTER_NAME)" -var="enable_observability=$(ENABLE_OBSERVABILITY)" -var-file="$(LOCAL_DIR)/local.tfvars.json"

down:
	@if [ -f "$(TF_DIR)/terraform.tfstate" ]; then \
		terraform -chdir=$(TF_DIR) destroy -auto-approve -input=false -var="cluster_name=$(CLUSTER_NAME)" || true; \
	fi
	kind delete cluster --name "$(CLUSTER_NAME)" || true
	rm -f "$(TF_DIR)/$(CLUSTER_NAME)-config"

gcp-up:
	@test -n "$(GCP_PROJECT_ID)" || (echo "Set GCP_PROJECT_ID=<your-gcp-project-id>" && exit 1)
	@if [ ! -f "$(LOCAL_DIR)/local.tfvars.json" ]; then $(MAKE) dev-creds; fi
	terraform -chdir=$(GCP_TF_DIR) init -input=false
	terraform -chdir=$(GCP_TF_DIR) apply -auto-approve -input=false \
		-target=google_project_service.required \
		-target=google_artifact_registry_repository.containers \
		-var="project_id=$(GCP_PROJECT_ID)" \
		-var="region=$(GCP_REGION)" \
		-var="cluster_name=$(GCP_CLUSTER_NAME)" \
		-var="artifact_registry_repo=$(GCP_ARTIFACT_REPO)"
	gcloud auth configure-docker "$(GCP_REGION)-docker.pkg.dev" --quiet
	docker build --platform linux/amd64 -f services/gateway-api/Dockerfile -t "$(GCP_REGION)-docker.pkg.dev/$(GCP_PROJECT_ID)/$(GCP_ARTIFACT_REPO)/ai-gateway-api:$(GCP_IMAGE_TAG)" .
	docker build --platform linux/amd64 -f services/mcp-runtime/Dockerfile -t "$(GCP_REGION)-docker.pkg.dev/$(GCP_PROJECT_ID)/$(GCP_ARTIFACT_REPO)/ai-mcp-runtime:$(GCP_IMAGE_TAG)" .
	docker build --platform linux/amd64 -f services/mock-llm/Dockerfile -t "$(GCP_REGION)-docker.pkg.dev/$(GCP_PROJECT_ID)/$(GCP_ARTIFACT_REPO)/ai-mock-llm:$(GCP_IMAGE_TAG)" .
	docker push "$(GCP_REGION)-docker.pkg.dev/$(GCP_PROJECT_ID)/$(GCP_ARTIFACT_REPO)/ai-gateway-api:$(GCP_IMAGE_TAG)"
	docker push "$(GCP_REGION)-docker.pkg.dev/$(GCP_PROJECT_ID)/$(GCP_ARTIFACT_REPO)/ai-mcp-runtime:$(GCP_IMAGE_TAG)"
	docker push "$(GCP_REGION)-docker.pkg.dev/$(GCP_PROJECT_ID)/$(GCP_ARTIFACT_REPO)/ai-mock-llm:$(GCP_IMAGE_TAG)"
	terraform -chdir=$(GCP_TF_DIR) apply -auto-approve -input=false \
		-var="project_id=$(GCP_PROJECT_ID)" \
		-var="region=$(GCP_REGION)" \
		-var="cluster_name=$(GCP_CLUSTER_NAME)" \
		-var="artifact_registry_repo=$(GCP_ARTIFACT_REPO)" \
		-var="image_tag=$(GCP_IMAGE_TAG)" \
		-var="enable_gemini_provider=$(ENABLE_GEMINI_PROVIDER)" \
		-var="gemini_api_key=$(GEMINI_API_KEY)" \
		-var-file="$(LOCAL_DIR)/local.tfvars.json"

gcp-down:
	@test -n "$(GCP_PROJECT_ID)" || (echo "Set GCP_PROJECT_ID=<your-gcp-project-id>" && exit 1)
	@if [ -f "$(GCP_TF_DIR)/terraform.tfstate" ]; then \
		terraform -chdir=$(GCP_TF_DIR) destroy -auto-approve -input=false \
			-var="project_id=$(GCP_PROJECT_ID)" \
			-var="region=$(GCP_REGION)" \
			-var="cluster_name=$(GCP_CLUSTER_NAME)" \
			-var="artifact_registry_repo=$(GCP_ARTIFACT_REPO)"; \
	fi

test:
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run python scripts/validate_aliases.py
	helm lint $(CHART_DIR)
	terraform -chdir=$(TF_DIR) fmt -check
	terraform -chdir=$(GCP_TF_DIR) fmt -check

checkov:
	uvx --from checkov checkov -d $(TF_DIR) --framework terraform --compact --quiet
	uvx --from checkov checkov -d $(GCP_TF_DIR) --framework terraform --compact --quiet
	helm template ai-gateway $(CHART_DIR) --namespace ai-gateway > /tmp/helm-rendered.yaml
	uvx --from checkov checkov -f /tmp/helm-rendered.yaml --framework kubernetes --compact --quiet

trivy: build-images
	@mkdir -p "$(LOCAL_DIR)" "$(HOME)/.cache/trivy"
	@if command -v trivy >/dev/null 2>&1; then \
		trivy image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 1 ai-gateway-api:dev; \
		trivy image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 1 ai-mcp-runtime:dev; \
		trivy image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 1 ai-mock-llm:dev; \
		trivy image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 0 --format sarif --output "$(LOCAL_DIR)/litellm-trivy.sarif" ghcr.io/berriai/litellm:1.84.0; \
	else \
		docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(HOME)/.cache/trivy:/root/.cache" aquasec/trivy:latest image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 1 ai-gateway-api:dev; \
		docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(HOME)/.cache/trivy:/root/.cache" aquasec/trivy:latest image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 1 ai-mcp-runtime:dev; \
		docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(HOME)/.cache/trivy:/root/.cache" aquasec/trivy:latest image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 1 ai-mock-llm:dev; \
		docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(HOME)/.cache/trivy:/root/.cache" -v "$(LOCAL_DIR):/out" aquasec/trivy:latest image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 0 --format sarif --output /out/litellm-trivy.sarif ghcr.io/berriai/litellm:1.84.0; \
	fi

smoke:
	uv run python scripts/smoke_test.py
