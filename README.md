# Protection Gateway

Upload text or email, bind it to a task policy, and inspect it with isolated
workers before releasing a source-backed result. The current local workflow
uses Kimi K3. Email actions are simulations requiring separate confirmation.

```sh
make setup                  # Python 3.12; override with PYTHON=python3.11 if needed
# Save KIMI_API_KEY in .env; deploy/local.env.example shows optional settings.
make check                  # Verifies the configured runtime and sandbox
make run                    # http://127.0.0.1:8766/ui
```

Sign in using the local token in `var/runtime/login-token`. The token is
separate from your Kimi key. `make run` explicitly enables loopback development
storage; production deployment and native account verification are separate.

```sh
make test                   # Unit and contract checks
make test-e2e               # Real HTTP/core/workers/SLIM; deterministic inference
make smoke                  # Running gateway, live Kimi K3, synthetic inputs
```

See [the pipeline, test results and repeatable browser steps](docs/testing.md).
