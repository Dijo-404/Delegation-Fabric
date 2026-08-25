.PHONY: bootstrap lint format format-check typecheck test-core test-integration test-security test-e2e check \
        infra seed deploy-agents deploy demo demo-preflight attack-injection attack-escalation clean

PYTHON := python3
UV     := uv

## ─── Setup ────────────────────────────────────────────────────────────────────

bootstrap:
	$(UV) sync --all-extras
	$(UV) run pre-commit install
	@echo "Bootstrap complete."

## ─── Quality ──────────────────────────────────────────────────────────────────

lint:
	$(UV) run ruff check packages/ apps/ tests/
	@echo "Lint clean."

format:
	$(UV) run ruff format packages/ apps/ tests/

format-check:
	$(UV) run ruff format --check packages/ apps/ tests/

typecheck:
	$(UV) run mypy packages/delegation_fabric_core packages/delegation_fabric_adapters apps

## ─── Tests ────────────────────────────────────────────────────────────────────

# term for humans, xml for codecov upload in CI.
COV := --cov=packages/delegation_fabric_core --cov-report=term-missing --cov-report=xml --cov-fail-under=85

test-core:
	$(UV) run pytest tests/unit/core/ -v $(COV)

test-integration:
	$(UV) run pytest tests/integration/ -v --no-cov

test-security:
	$(UV) run pytest tests/security/ -v --no-cov

test-e2e:
	$(UV) run pytest tests/e2e/ -v --no-cov

check: lint format-check typecheck test-core test-integration test-security test-e2e
	@echo "All checks passed."

## ─── Infrastructure ───────────────────────────────────────────────────────────

infra:
	@echo "Applying Terraform..."
	cd infra/environments/hackathon && terraform init && terraform apply -auto-approve

seed:
	$(UV) run python seed/erp/seed.py
	$(UV) run python seed/poisoned_invoice/seed.py
	@echo "Seed complete."

## ─── Deploy ───────────────────────────────────────────────────────────────────

deploy-agents:
	cd apps/agents/invoice_reconciliation && $(UV) run python deploy.py
	cd apps/agents/procurement_exception && $(UV) run python deploy.py
	cd apps/agents/treasury_approval && $(UV) run python deploy.py

deploy:
	@echo "Deploying Cloud Run services..."
	gcloud run deploy control-plane \
	    --source apps/control_plane \
	    --region $${GOOGLE_CLOUD_LOCATION:-asia-south1} \
	    --service-account df-control-plane@$${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com \
	    --no-allow-unauthenticated
	gcloud run deploy execution-gateway \
	    --source apps/execution_gateway \
	    --region $${GOOGLE_CLOUD_LOCATION:-asia-south1} \
	    --service-account df-execution-gateway@$${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com \
	    --no-allow-unauthenticated
	gcloud run deploy worker \
	    --source apps/worker \
	    --region $${GOOGLE_CLOUD_LOCATION:-asia-south1} \
	    --service-account df-worker@$${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com \
	    --no-allow-unauthenticated

## ─── Demo & Attacks ───────────────────────────────────────────────────────────

demo-preflight:
	$(UV) run python seed/timeline/preflight.py

attack-injection:
	$(UV) run pytest tests/security/test_attacks.py::test_attack_1_prompt_injection_denied -v --no-cov

attack-escalation:
	$(UV) run pytest tests/security/test_attacks.py::test_attack_2_cross_agent_escalation_denied -v --no-cov

demo:
	$(UV) run python seed/timeline/demo.py

## ─── Clean ────────────────────────────────────────────────────────────────────

clean:
	rm -rf .coverage .pytest_cache __pycache__ dist .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
