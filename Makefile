# Repeatable developer commands (owned by teammate B). Uses the pinned environment in .venv.
PY := .venv/bin/python
# First supported interpreter on PATH (newest first). Override with PYTHON=/path/to/python3.12.
PYTHON ?= $(shell for p in python3.13 python3.12 python3.11; do command -v $$p >/dev/null 2>&1 && echo $$p && break; done)
PORT ?= 8766
# Development only. REPLAY=record caches live model replies; REPLAY=replay serves them offline (labeled REPLAY in the UI).
REPLAY ?=
PYTHON_HELP := Install one with uv (uv python install 3.12) or pyenv (pyenv install 3.12), see README, then run: make setup PYTHON=/path/to/python3.12

.PHONY: setup test test-isolation test-e2e smoke check doctor eval run lock

setup:
	@if [ -z "$(PYTHON)" ]; then echo "error: no Python 3.11 or later found on PATH. $(PYTHON_HELP)" >&2; exit 1; fi
	@if ! command -v "$(PYTHON)" >/dev/null 2>&1; then echo "error: '$(PYTHON)' was not found. $(PYTHON_HELP)" >&2; exit 1; fi
	@"$(PYTHON)" -c 'import sys; v = sys.version_info; sys.exit(0 if v >= (3, 11) else "error: $(PYTHON) is Python %d.%d; Python 3.11 or later is required. $(PYTHON_HELP)" % (v[0], v[1]))'
	@echo "Using $(PYTHON) ($$("$(PYTHON)" -c 'import platform; print(platform.python_version())'))"
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
	PG_PORT=$(PORT) PG_MODEL_REPLAY=$(REPLAY) $(PY) -m protection_gateway.bootstrap --dev --check

# Demo preflight: API key set (never printed), SLIM round trip, sandbox, model broker reply, port free.
# Add ARGS=--offline to skip the one tiny live provider call.
doctor:
	PG_MODEL_REPLAY=$(REPLAY) $(PY) scripts/doctor.py --port $(PORT) $(ARGS)

# Naive agent vs. gateway conditions on eval/corpus (live Kimi, replies cached in var/eval-cache).
# REPLAY=replay re-scores offline from that cache. Writes eval/results.{json,md} and eval/chart.svg.
eval:
	$(PY) eval/run_eval.py --replay "$(REPLAY)" $(ARGS)

run:
	PG_PORT=$(PORT) PG_MODEL_REPLAY=$(REPLAY) $(PY) -m protection_gateway.bootstrap --dev

lock:
	uv pip compile pyproject.toml --extra anthropic --extra dev --universal --generate-hashes --python-version 3.11 -o requirements.lock
