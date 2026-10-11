# Protection Gateway

Protection Gateway accepts plain-text documents and email, checks them against a task you choose, and releases a source-backed result only when the gateway permits it. Isolated workers inspect the content; instructions inside a document cannot change the task policy or approve an action.

The local development workflow uses Kimi K3 for live inspections. Email actions are simulations and never send real email. This guide covers local setup, running the app, trying the sample fixtures, and repeating the checks.

## Requirements

- macOS with the system sandbox available, or another host where `make check` confirms the required isolation support.
- Python 3.11 or later. The setup command defaults to Python 3.12.
- A Kimi API key for live document inspections. The unit and deterministic end-to-end test suites do not need a key.

## Set up the local app

From the repository root, create the pinned virtual environment and install the hashed dependencies:

```sh
make setup
```

If Python 3.12 is not installed, choose an available supported version:

```sh
make setup PYTHON=python3.11
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

## Scan a folder

1. Sign in, then drag files or a folder into the large drop area, or use **Choose files** / **Choose a folder**. Nested files are included with their relative paths.
2. Select **Scan Now**. A progress bar shows upload preparation and completed required checks, with the files in the current scan listed below. The agents inspect supported files together against a read-only summary task; progress does not imply a file-by-file inspection order.
3. When the scan finishes, suspicious files appear first with plain-language findings and **Review evidence** buttons. Files with no findings and any uninspected files are listed separately by status. The progress bar reaches 100% only when coverage is complete. Incomplete checks remain clearly labeled. Advanced task policies and permitted-result controls are available under **More options**.

Folder scans support text files with `.txt`, `.md`, `.csv`, `.json`, `.log`, `.py`, `.js`, `.ts`, `.css`, `.yaml`, `.yml`, `.xml`, `.html`, `.htm`, and `.eml` extensions. This checks document content for prompt injection; it is not an antivirus or executable malware scanner. PDFs, images, archives, and other unsupported files appear in the report as uninspected and prevent complete folder coverage. Empty directories have no files to inspect.

A selection may contain up to 100 file entries, with at most 10 supported sources, 1 MiB per source, and 2 MiB of supported content in total. Selections exceeding the inspection budget are held instead of being silently split or partially approved. Extraction also remains subject to the gateway's existing text limits.

For a smaller four-file check, select [`examples/folder-scan-test`](examples/folder-scan-test). Only `injected-message.txt` contains seeded hostile instructions; the other three files are ordinary fictional content.

For a runnable nested-folder example, select [`examples/prompt-injection-test-repo`](examples/prompt-injection-test-repo). It contains 10 supported files, including three inert prompt-injection fixtures. Its README lists the expected suspicious paths and how to run the ordinary project.

After uploading, the report displays a folder ID. An authenticated MCP client can call `inspect_folder` with that `folder_id`, then `get_folder_status` to retrieve the same per-file report. Local filesystem paths are not accepted by these tools: choose the folder in the browser first to authorize its files. Restart the gateway after updating and reconnect your MCP client so its tool list includes the two folder tools.

If model inspections fail, the folder report shows the provider error when available and keeps the files uninspected. On macOS, Python installations with an empty default trust store use `/etc/ssl/cert.pem` for Kimi HTTPS connections. Certificate and hostname verification remain enabled; an explicitly configured `SSL_CERT_FILE` or `SSL_CERT_DIR` is respected.

Malformed model reports permit at most two fresh-report retries within the original inspection budget and deadline. Every replacement report must pass the same role, source-reference, full-view, and task-output validation. Persistent errors keep the scan incomplete; a previously flagged file remains flagged. Report repair does not repeat simulated tool actions.

## Run checks

Run deterministic checks without live model calls or API charges:

```sh
make test                   # Unit and contract checks
node --test tests/adapters/scanner-ui.test.cjs  # File selection and progress UI checks
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

- Single-file uploads accept `.txt` and `.eml`; folder uploads also accept the text extensions listed above. Unsupported relevant attachments and incomplete inspection coverage keep content held.
- This gateway protects only the workflow routed through this application. Native chat uploads, pasted text, browsing, other connectors, and a native app’s final response are outside this local gateway’s enforcement.
- `make run` enables loopback-only development mode and local private storage. It is not a production deployment configuration.
- The simulated action flow records a dummy effect only. Real email sending, payments, and external actions are not enabled.
