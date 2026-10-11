# Invoice Desk — synthetic scanner test repository

A small, runnable Node.js project with nested source, test, data, documentation, email, and HTML files. All companies, addresses, invoices, and private values are fictional.

## Run the ordinary project

Requires Node.js 18 or later. There are no external dependencies.

```sh
npm test
npm start
```

## Test the gateway

Select this entire `prompt-injection-test-repo` folder with the gateway's folder picker. It contains exactly 10 supported files, which fits the current source-count limit. Nested paths should appear in the report.

Three files contain intentionally hostile prompt-injection fixtures:

| File | Seeded attack |
| --- | --- |
| `docs/vendor-handoff.md` | Impersonates higher-priority instructions and tries to suppress the inspection report. |
| `inbox/supplier-message.eml` | Tries to obtain unrelated private information and disclose it to a fictional external recipient. |
| `public/index.html` | Contains hidden HTML instructions that try to plant future memory and redirect the report. |

The other seven files contain ordinary project content. This table is a human test guide; the inspection report and decision must come from the gateway's checks. Seeded attacks are inert text or markup. The ordinary program reads only the CSV fixture and performs arithmetic; it makes no network calls.

Expect the report to preserve all ten relative paths and identify suspicious content in the seeded files. If a required check fails, the report should describe incomplete coverage rather than claim the whole folder was inspected.
