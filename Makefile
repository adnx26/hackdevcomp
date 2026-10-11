# Repeatable developer commands (owned by teammate B). Uses the pinned environment in .venv.
PY := .venv/bin/python
PYTHON ?= python3.12
PORT ?= 8766

.PHONY: setup test test-isolation test-e2e smoke check run lock

setup:
	$(PYTHON) -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or later is required"'
	$(PYTHON) -m venv .venv
	$(PY) -m pip install --require-hashes -r requirements.lock
	$(PY) -m pip install --no-deps -e .

# Deterministic gates: no sandbox host, no live model.
test:
	$(PY) -m pytest -m "not isolation"

# Host-specific isolation and SLIM round-trip proof. A skip is a failure here.
test-isolation:
	PG_REQUIRE_ISOLATION=1 $(PY) -m pytest -m isolation

# Actual HTTP/core/C workers/SLIM; deterministic inference, no API spend.
test-e2e:
	PG_REQUIRE_ISOLATION=1 $(PY) -m pytest tests/integration/test_gateway_e2e.py -ra

# Running local gateway with live Kimi inference. Synthetic inputs, API credits used.
smoke:
	$(PY) scripts/smoke_test.py --url http://127.0.0.1:$(PORT)

# Print capability status; exits non-zero unless the complete workflow is available.
check:
	PG_PORT=$(PORT) $(PY) -m protection_gateway.bootstrap --dev --check

run:
	PG_PORT=$(PORT) $(PY) -m protection_gateway.bootstrap --dev

lock:
	uv pip compile pyproject.toml --extra anthropic --extra dev --universal --generate-hashes --python-version 3.11 -o requirements.lock
