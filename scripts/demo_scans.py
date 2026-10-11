"""Run the demo inputs against a running gateway and print each decision.

Use it twice: once against a gateway started in record mode (live Kimi; the
replies land in the replay cache), then against the same gateway restarted in
replay mode to confirm every demo input replays offline with the same outcome.

    PG_REPLAY_DIR=demo/replay-cache make run REPLAY=record     # terminal 1
    .venv/bin/python scripts/demo_scans.py --save demo/demo_scans.json   # terminal 2

    PG_REPLAY_DIR=demo/replay-cache make run REPLAY=replay     # terminal 1
    .venv/bin/python scripts/demo_scans.py --expect demo/demo_scans.json # terminal 2
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from protection_gateway.core.folders import media_for_path  # noqa: E402

_spec = importlib.util.spec_from_file_location("gateway_smoke", REPO / "scripts" / "smoke_test.py")
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

FOLDERS = ["examples/folder-scan-test", "examples/prompt-injection-test-repo"]
FILES = [
    ("eval/corpus/redteam/ap-policy-footer.txt", "extract_invoice"),
    ("eval/corpus/redteam/bec-vendor-bank-change.eml", "extract_invoice"),
    ("eval/corpus/redteam/meeting-action-items.txt", "summarize_email"),
    ("eval/corpus/redteam/ceo-wire-fraud.eml", "summarize_email"),
    ("eval/corpus/benign/invoice-acme.txt", "extract_invoice"),
]


def scan_folder(client, root: Path) -> dict:
    entries = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        media = media_for_path(relative)
        entry = {"path": relative, "size_bytes": path.stat().st_size, "status": "STORED" if media else "UNSUPPORTED_FORMAT"}
        if media:
            entry["resource_id"] = client.upload(path.read_bytes(), media)
        entries.append(entry)
    folder = client.request("/v1/folders", {"entries": entries}, expected=201)
    client.request(f"/v1/folders/{folder['folder_id']}/inspect", {}, expected=202)
    started = time.monotonic()
    while True:
        status = client.request(f"/v1/folders/{folder['folder_id']}")
        if status["state"] in {"DECIDED", "FAILED", "CANCELED"} or time.monotonic() - started > 330:
            break
        time.sleep(1)
    scan = client.request(f"/v1/scans/{status['scan_id']}") if status.get("scan_id") else {}
    return {"decision": status["state"] if status["state"] != "DECIDED" else scan.get("decision"),
            "reason_codes": sorted(scan.get("reason_codes", [])), "inference_mode": scan.get("inference_mode"),
            "flagged": sorted(f["path"] for f in status["files"] if f["status"] == "FLAGGED"),
            "seconds": round(time.monotonic() - started, 1)}


def scan_file(client, path: Path, policy: str) -> dict:
    media = media_for_path(path.name)
    started = time.monotonic()
    _, scan = client.start([client.upload(path.read_bytes(), media)], policy)
    status = client.wait(scan, timeout=330)
    return {"decision": status["decision"] or status["state"], "reason_codes": sorted(status["reason_codes"]),
            "inference_mode": status.get("inference_mode"), "seconds": round(time.monotonic() - started, 1)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:8766")
    parser.add_argument("--token-file", type=Path, default=REPO / "var" / "runtime" / "login-token")
    parser.add_argument("--save", type=Path, help="write the outcomes here (after recording)")
    parser.add_argument("--expect", type=Path, help="compare outcomes with a saved file (after restarting in replay)")
    args = parser.parse_args(argv)

    client = smoke.Client(args.url, args.token_file.read_text().strip())
    outcomes = {}
    for folder in FOLDERS:
        outcomes[folder] = scan_folder(client, REPO / folder)
        print(f"{folder:<48} {json.dumps(outcomes[folder])}", flush=True)
    for path, policy in FILES:
        key = f"{path} [{policy}]"
        outcomes[key] = scan_file(client, REPO / path, policy)
        print(f"{key:<48} {json.dumps(outcomes[key])}", flush=True)

    if args.save:
        args.save.write_text(json.dumps(outcomes, indent=2) + "\n")
        print(f"saved {args.save}")
    if args.expect:
        expected = json.loads(args.expect.read_text())
        mismatches = [k for k in expected if {f: v for f, v in outcomes.get(k, {}).items() if f not in ("seconds", "inference_mode")}
                      != {f: v for f, v in expected[k].items() if f not in ("seconds", "inference_mode")}]
        print("replay matches the recording" if not mismatches else f"MISMATCH: {mismatches}")
        return 1 if mismatches else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
