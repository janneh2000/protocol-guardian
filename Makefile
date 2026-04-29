# Protocol Guardian — quick targets.
# For the full agent loop see README → "Step-by-step setup".

.PHONY: verify install-deps swarm dashboard help

help:
	@echo "Protocol Guardian — make targets"
	@echo ""
	@echo "  make verify        Run the no-secrets smoke test (~30s, no API keys)"
	@echo "  make install-deps  npm install + pip install -r requirements.txt"
	@echo "  make swarm         Boot the 3-node Gensyn AXL demo via docker-compose"
	@echo "  make dashboard     Serve the operator dashboard at localhost:8080"
	@echo ""
	@echo "For the full agent loop see README → 'Step-by-step setup'."

verify:
	@python3 scripts/smoke_test.py

install-deps:
	npm install
	python3 -m pip install -r requirements.txt

swarm:
	docker compose -f agent/axl/docker-compose.yml up --build

dashboard:
	@echo "Serving dashboard at http://localhost:8080"
	@cd dashboard && python3 -m http.server 8080
