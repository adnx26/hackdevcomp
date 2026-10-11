# Public research proof-of-concept evaluation

Source: https://github.com/greshake/llm-security at commit c312325bee5f16d8f6524bd6f41e1510c5623a1e (MIT; license included).

Select only `scan-folder` in the gateway folder picker. It contains four attack payloads and two benign controls. Labels and provenance are outside that folder so they cannot guide the scanner. `manifest.json` records transformations and file hashes. No upstream scripts are executed.

These are external published research demonstrations, not confirmed incident samples. Payload literals are preserved, including historical destinations; the gateway receives them as untrusted text and cannot contact these destinations. The hidden-payload article reproduces the upstream midpoint insertion. The gateway uses its fixed read-only summary policy, not the original authors' agent, tools, model, or task: this is a detection/holding evaluation, not a reproduction of their attack-success benchmark. The memory example was originally injected directly; here its literal is tested as an uploaded document.

Run `python3 scripts/evaluate_public_poc.py` while the local gateway is running. This sends the public fixtures to the configured model provider and uses API credits. Reports go to ignored `var/evaluations/`; no API key or login token is saved in them. Two mixed-folder runs and one benign-only run are recorded. Incomplete inspection is reported separately and does not count as successful detection or a missed attack. Findings are allegations; compare recorded evidence with the source passages.
