# Repeatable developer commands (owned by teammate B). Uses the pinned environment in .venv.
PY := .venv/bin/python

.PHONY: setup test test-isolation check run lock

setup:
	python3 -m venv .venv
	$(PY) -m pip install --require-hashes -r requirements.lock
	$(PY) -m pip install --no-deps -e .

# Deterministic gates: no sandbox host, no live model.
test:
	$(PY) -m pytest -m "not isolation"

# Host-specific isolation and SLIM round-trip proof. A skip is a failure here.
test-isolation:
	PG_REQUIRE_ISOLATION=1 $(PY) -m pytest -m isolation

# Print capability status; exits non-zero unless the complete workflow is available.
check:
	$(PY) -m protection_gateway.bootstrap --check

run:
	$(PY) -m protection_gateway.bootstrap

lock:
	uv pip compile pyproject.toml --extra anthropic --extra dev --universal --generate-hashes --python-version 3.11 -o requirements.lock
