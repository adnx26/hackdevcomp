# Protection Gateway

Protection Gateway accepts plain-text documents and email, checks them against a task you choose, and releases a source-backed result only when the gateway permits it. Isolated workers inspect the content; instructions inside a document cannot change the task policy or approve an action.

The local development workflow uses Kimi K3 for live inspections. Email actions are simulations and never send real email. This guide covers local setup, running the app, trying the sample fixtures, and repeating the checks.

## Requirements

- macOS with the system sandbox available, or another host where `make check` confirms the required isolation support.
- Python 3.11 or later (3.12 recommended; pinned in `.python-version`). `make setup` uses the newest of `python3.13`, `python3.12` or `python3.11` on your `PATH` and stops with an error if none is available or the chosen interpreter is older than 3.11.
- A Kimi API key for live document inspections. The unit and deterministic end-to-end test suites do not need a key.

## Set up the local app

From the repository root, create the pinned virtual environment and install the hashed dependencies:

```sh
make setup
```

To choose a specific interpreter, pass it explicitly:

```sh
make setup PYTHON=python3.11
```

If you don't have Python 3.11 or later, install 3.12 with either tool. Both read the repository's `.python-version`:

```sh
# uv (https://docs.astral.sh/uv/)
uv python install 3.12
make setup PYTHON="$(uv python find 3.12)"

# pyenv (https://github.com/pyenv/pyenv)
pyenv install 3.12
make setup PYTHON="$(pyenv which python)"
```

Create a local environment file and add your Kimi API key. `.env` is ignored by Git; never commit or paste the key into the browser.

```sh
cp deploy/local.env.example .env
```

Edit `.env` and replace `replace-with-your-key` with your key. The example also sets the provider, model, reasoning effort, timeout, output limit, and local port. The default model is `kimi-k3`.

Check that the complete workflow is available, then start the gateway:

```sh
make check
make run
```

Open [http://127.0.0.1:8766/ui](http://127.0.0.1:8766/ui). The first development startup creates a local sign-in token at `var/runtime/login-token`. Enter that token in the page’s **Local gateway login token** field. It is separate from your Kimi API key.

Keep the terminal running while you use the app. Stop the gateway with Ctrl-C. To use another port, use the same port for both commands, for example `make run PORT=8877`; then open `http://127.0.0.1:8877/ui`.

## Try a document

1. In the UI, upload a `.txt` or `.eml` file. Uploading stores it privately but does not start an inspection or release a result.
2. Select the uploaded resource and choose the task policy that matches your goal:

   | Policy | Use it for |
   | --- | --- |
   | **Extract invoice fields** | Extract the invoice ID, amount, currency, and due date from an invoice. |
   | **Summarize email** | Create a source-backed summary of an email or text document. |
   | **Simulate a confirmed email action** | Test the separate action proposal and confirmation flow. This records a simulation only; it sends no email. |

3. Select **Start inspection** and wait for the gateway decision. While checks are running, the result stays unavailable.
4. If the gateway permits a result, select **View permitted result**. Source references and disclosure labels accompany the result.
5. If the gateway holds the content, read the plain-language reason and supporting evidence. Evidence is shown separately from the controlled assistant. For an eligible **REVIEW**, you can inspect the evidence and request a read-only exception; the decision remains REVIEW.

For a first successful invoice flow, upload `tests/fixtures/e2e/invoice.txt` and choose **Extract invoice fields**. To exercise prompt-injection handling, upload `tests/fixtures/e2e/injected-invoice.txt` or `tests/fixtures/e2e/complex-injected-invoice.txt` with the same policy. The injected text is untrusted document content; expect the gateway to hold it for review or quarantine rather than release it automatically.

The complex fixture contains conflicting invoice values and several synthetic injection styles, including fake role labels, tool-call-shaped text, markup, encoded text, Unicode lookalikes, repetition, and a final-position instruction. Its secrets, companies, and destinations are fictional.

## Run checks

Run deterministic checks without live model calls or API charges:

```sh
make test                   # Unit and contract checks
make test-e2e               # Real local HTTP/core/worker/SLIM stack; deterministic inference
make test-isolation         # Host-specific sandbox checks
.venv/bin/python -m pip check
```

`make test-e2e` uses the real local stack and sandboxed workers, while replacing only provider inference with deterministic responses. A missing isolation capability fails the target.

For a live provider smoke test, first start the gateway with `make run` in one terminal. In another terminal, run:

```sh
make smoke
```

This calls Kimi and uses API credits. It submits only the included synthetic invoice, injected instruction, and meeting text; it does not inspect your private documents or send email. Provider decisions can vary, and provider errors keep content held.

For a complete pipeline description, test results, and repeatable browser steps, see [docs/testing.md](docs/testing.md).

## Supported scope and limitations

- The local UI accepts `.txt` and `.eml` uploads. Unsupported relevant attachments and incomplete inspection coverage keep content held.
- This gateway protects only the workflow routed through this application. Native chat uploads, pasted text, browsing, other connectors, and a native app’s final response are outside this local gateway’s enforcement.
- `make run` enables loopback-only development mode and local private storage. It is not a production deployment configuration.
- The simulated action flow records a dummy effect only. Real email sending, payments, and external actions are not enabled.
