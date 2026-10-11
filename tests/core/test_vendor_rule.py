"""Deterministic vendor bank-details rule: registry mismatch holds content for review."""

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from protection_gateway.core.vendors import bank_mismatch, find_ibans, load_registry

from .support import INVOICE_TEXT, V, Harness

REGISTRY = {"vendors": [{"name": "Acme Analytics Ltd", "aliases": ["Acme"], "ibans": ["GB29 NWBK 6016 1331 9268 19"]}]}


class VendorRuleTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        path = Path(tempfile.mkdtemp(prefix="pg-vendors-")) / "vendors.json"
        path.write_text(json.dumps(REGISTRY))
        self.h.service.config = replace(self.h.service.config, vendor_registry_path=str(path))
        self.p = self.h.api()

    def tearDown(self):
        self.h.close()

    def scan(self, text):
        res = self.h.upload(self.p, text)
        ts = self.h.session(self.p, [res["resource_id"]], "extract_invoice")
        self.count = getattr(self, "count", 0) + 1
        scan_id = self.h.scan(self.p, ts["task_session_id"], f"k{self.count}")["scan_id"]
        self.h.complete_clean(scan_id, self.h.invoice_output(scan_id, text))  # every inspector clean
        return self.h.service.get_scan_status(self.p, scan_id)

    def test_changed_bank_details_are_held_even_when_inspectors_are_clean(self):
        status = self.scan(INVOICE_TEXT + "\nNew bank details: IBAN GB00 EXFL 0000 1111 2222 33\n")
        self.assertEqual((status["decision"], status["reason_codes"]), ("REVIEW", ["VENDOR_BANK_MISMATCH"]))
        self.assertFalse(status["review"]["eligible"])  # a verified finding cannot be waived
        self.assertEqual(status["decision_trace"]["deciding_rule"], "vendor_bank_details")
        self.assertEqual({i["verdict"] for i in status["inspectors"]}, {"CLEAN"})

    def test_registered_account_or_unknown_vendor_is_allowed(self):
        self.assertEqual(self.scan(INVOICE_TEXT + "\nPay to GB29NWBK60161331926819\n")["decision"], "ALLOW_UNDER_POLICY")
        unknown = INVOICE_TEXT.replace("Acme", "Contoso") + "\nIBAN GB00 EXFL 0000 1111 2222 33\n"
        self.assertEqual(self.scan(unknown)["decision"], "ALLOW_UNDER_POLICY")

    def test_no_registry_means_no_rule(self):
        self.h.service.config = replace(self.h.service.config, vendor_registry_path=None)
        status = self.scan(INVOICE_TEXT + "\nIBAN GB00 EXFL 0000 1111 2222 33\n")
        self.assertEqual(status["decision"], "ALLOW_UNDER_POLICY")


class VendorHelperTests(unittest.TestCase):
    def test_iban_detection_and_normalization(self):
        text = "pay GB00 EXFL 0000 1111 2222 33 or GB29NWBK60161331926819; ref INV-2041; phone +44 20 7946 0958"
        self.assertEqual(find_ibans(text), {"GB00EXFL00001111222233", "GB29NWBK60161331926819"})

    def test_mismatch_logic(self):
        registry = load_registry(None) or tuple()
        self.assertFalse(bank_mismatch(["Acme IBAN GB00EXFL00001111222233"], registry))
        path = Path(tempfile.mkdtemp()) / "v.json"
        path.write_text(json.dumps(REGISTRY))
        registry = load_registry(str(path))
        self.assertTrue(bank_mismatch(["Acme Analytics Ltd", "IBAN GB00 EXFL 0000 1111 2222 33"], registry))  # across views
        self.assertFalse(bank_mismatch(["Acme pays to GB29 NWBK 6016 1331 9268 19"], registry))
        self.assertFalse(bank_mismatch(["Acme invoice, no bank details"], registry))
        self.assertEqual(load_registry(str(path.parent / "missing.json")), ())

    def test_demo_registry_loads(self):
        registry = load_registry(str(Path(__file__).resolve().parents[2] / "demo" / "vendors.json"))
        self.assertEqual({v.name for v in registry}, {"Acme Analytics Ltd", "Globex Consulting GmbH", "Initech UK"})


if __name__ == "__main__":
    unittest.main()
