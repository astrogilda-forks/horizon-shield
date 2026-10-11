"""Exercise the workflow's exact comparison code without calling a live ledger."""

import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.error


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/probity-witness-reader.yml"


def comparison_source():
    bodies = re.findall(
        r"^          python3 - <<'EOF'\n(.*?)^          EOF$",
        WORKFLOW.read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )
    selected = []
    for body in bodies:
        source = "".join(line[10:] for line in body.splitlines(keepends=True))
        tree = ast.parse(source)
        if any(isinstance(node, ast.FunctionDef) and node.name == "check_one" for node in tree.body):
            selected.append(source)
    if len(selected) != 1:
        raise RuntimeError("expected exactly one workflow ledger comparison")
    return selected[0]


comparison = types.ModuleType("horizon_ledger_comparison_controls")
exec(compile(comparison_source(), str(WORKFLOW), "exec"), comparison.__dict__)


def envelope(text):
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {"sha": sha, "record": {"record_canonical": text}}


class LedgerComparisonTests(unittest.TestCase):
    def setUp(self):
        self.record = envelope('{"target":"/a2a"}')
        self.pin = {"record_sha256": self.record["sha"]}

    def check(self, response, name="a"):
        return comparison.check_one(name, self.pin, self.record, lambda url: response)

    def raising(self, error):
        def fetch(url):
            raise error

        return comparison.check_one("a", self.pin, self.record, fetch)

    def test_two_identical_records_establish_match(self):
        report = comparison.summarize([self.check(self.record), self.check(self.record, "b")])
        self.assertEqual((report["status"], report["exit_code"]), ("match", 0))

    def test_pin_mismatch_refuses_before_network(self):
        def forbidden(url):
            self.fail("invalid local evidence must not trigger a request")

        result = comparison.check_one("a", {"record_sha256": "0" * 64}, self.record, forbidden)
        self.assertEqual((result["status"], result["code"]), ("mismatch", "invalid_fixture"))

    def test_envelope_digest_mismatch_refuses_before_network(self):
        damaged = dict(self.record, sha="0" * 64)
        result = comparison.check_one("a", self.pin, damaged, lambda url: self.fail("unexpected request"))
        self.assertEqual(result["code"], "invalid_fixture")

    def test_different_ledger_record_refuses(self):
        result = self.check(envelope('{"target":"/mcp"}'))
        self.assertEqual((result["status"], result["code"]), ("mismatch", "different_canonical_bytes"))

    def test_semantically_equal_different_bytes_refuse(self):
        result = self.check(envelope('{ "target": "/a2a" }'))
        self.assertEqual(result["code"], "different_canonical_bytes")

    def test_http_403_is_unavailable_with_nonzero_exit(self):
        error = urllib.error.HTTPError("https://ledger.horizonshield.dev/", 403, "Forbidden", {}, None)
        result = self.raising(error)
        report = comparison.summarize([result, dict(result, witness="b")])
        self.assertEqual((report["status"], report["exit_code"]), ("unavailable", 2))
        self.assertEqual(result["http_status"], 403)
        self.assertEqual(result["fixture_status"], "match")

    def test_connection_failure_is_unavailable(self):
        self.assertEqual(self.raising(urllib.error.URLError("offline"))["status"], "unavailable")

    def test_timeout_is_unavailable(self):
        self.assertEqual(self.raising(TimeoutError("timeout"))["status"], "unavailable")

    def test_malformed_json_response_refuses(self):
        error = json.JSONDecodeError("malformed", "{", 1)
        self.assertEqual(self.raising(error)["code"], "invalid_ledger_response")

    def test_missing_or_falsy_canonical_record_refuses(self):
        for value in (
            None,
            {},
            {"record": {}},
            {"record": {"record_canonical": ""}},
            {"record": {"record_canonical": False}},
            {"record": {"record_canonical": 0}},
        ):
            with self.subTest(value=value):
                self.assertEqual(self.check(value)["code"], "invalid_ledger_response")

    def test_one_match_does_not_hide_one_unavailable(self):
        unavailable = self.raising(urllib.error.URLError("offline"))
        report = comparison.summarize([self.check(self.record, "b"), unavailable])
        self.assertEqual((report["status"], report["exit_code"]), ("unavailable", 2))

    def test_unavailable_does_not_hide_proven_mismatch(self):
        report = comparison.summarize(
            [self.check(envelope('{"target":"/mcp"}'), "b"), self.raising(urllib.error.URLError("offline"))]
        )
        self.assertEqual((report["status"], report["exit_code"]), ("mismatch", 1))

    def test_incomplete_pair_cannot_pass(self):
        self.assertEqual(comparison.summarize([self.check(self.record)])["exit_code"], 1)
        self.assertEqual(comparison.summarize([])["exit_code"], 1)

    def test_duplicate_witness_cannot_stand_in_for_missing_witness(self):
        self.assertEqual(comparison.summarize([self.check(self.record), self.check(self.record)])["exit_code"], 1)

    def test_unknown_or_missing_result_cannot_pass(self):
        for status in (None, False, "skipped", ""):
            with self.subTest(status=status):
                result = dict(self.check(self.record, "b"), status=status)
                self.assertEqual(comparison.summarize([self.check(self.record), result])["exit_code"], 1)


class WorkflowExitTests(unittest.TestCase):
    def run_comparison(self, mode):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / "fixtures").mkdir()
            (directory / "gate-results").mkdir()
            records = {"a": envelope('{"target":"/a2a"}'), "b": envelope('{"target":"/mcp"}')}
            pins = {}
            for name, record in records.items():
                filename = name + ".json"
                pins[name] = {"record_sha256": record["sha"], "envelope_file": filename}
                (directory / "fixtures" / filename).write_text(json.dumps(record), encoding="utf-8")
            (directory / "fixtures/pins.json").write_text(json.dumps(pins), encoding="utf-8")
            runner = (
                "import urllib.error\n"
                "namespace = {'__name__': 'workflow_exit_control'}\n"
                + "exec(compile(" + repr(comparison_source()) + ", 'workflow-comparison', 'exec'), namespace)\n"
                + "records = " + repr({record["sha"]: record for record in records.values()}) + "\n"
                + "mode = " + repr(mode) + "\n"
                + "def transport(url):\n"
                + "    if mode == 'unavailable':\n"
                + "        raise urllib.error.HTTPError(url, 403, 'Forbidden', {}, None)\n"
                + "    if mode == 'mismatch':\n"
                + "        return {'record': {'record_canonical': '{\"different\":true}'}}\n"
                + "    return records[url.rsplit('/', 1)[1]]\n"
                + "namespace['fetch_ledger'] = transport\n"
                + "namespace['main']()\n"
            )
            process = subprocess.run(
                [sys.executable, "-I", "-B", "-c", runner],
                cwd=directory,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(process.stderr, "")
            report = json.loads((directory / "gate-results/ledger-comparison.json").read_text())
            self.assertEqual(json.loads(process.stdout), report)
            self.assertEqual({row["witness"] for row in report["results"]}, {"a", "b"})
            return process.returncode, report

    def test_actual_workflow_main_accepts_two_matching_records(self):
        code, report = self.run_comparison("match")
        self.assertEqual((code, report["exit_code"], report["status"]), (0, 0, "match"))

    def test_actual_workflow_main_refuses_changed_canonical_bytes(self):
        code, report = self.run_comparison("mismatch")
        self.assertEqual((code, report["exit_code"], report["status"]), (1, 1, "mismatch"))

    def test_actual_workflow_main_refuses_unavailable_ledger(self):
        code, report = self.run_comparison("unavailable")
        self.assertEqual((code, report["exit_code"], report["status"]), (2, 2, "unavailable"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
