"""Export a reproducible offline report using an explicitly configured runner."""

import argparse
import importlib
import json
from pathlib import Path

from harness import evaluate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--factory", required=True, help="Offline runner factory module:function")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--repeats", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    module, name = args.factory.split(":", 1)
    manifest = json.loads(args.manifest.read_text())
    cases_document = json.loads(args.cases.read_text())
    cases = cases_document["scenarios"] if isinstance(cases_document, dict) else cases_document
    runner = getattr(importlib.import_module(module), name)()
    try:
        report = evaluate(runner, cases, repeats=args.repeats, manifest=manifest)
    finally:
        close = getattr(runner, "close", None)
        if close:
            close()
    args.output.write_text(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
