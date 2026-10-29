"""Offline integration tests: run the shell hook with mocked Cloudflare responses."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HOOK = Path(__file__).resolve().parents[1] / "update-cloudflare-ip4p.sh"
DOMAIN = "vpn.example.com"
ADDRESS = "2001::ca6c:c000:201"

MOCK_TOOL = r'''
import json
import math
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
if tool == "sleep":
    sys.exit(0)
if tool == "jsonfilter":
    obj = json.load(sys.stdin)
    values = [obj]
    for key, index in re.findall(r"\.([\w]+)(?:\[(\*|\d+)\])?", args[1]):
        next_values = []
        for value in values:
            value = value.get(key) if isinstance(value, dict) else None
            if index == "*":
                next_values.extend(value or [])
            elif index:
                if value and int(index) < len(value):
                    next_values.append(value[int(index)])
            elif value is not None:
                next_values.append(value)
        values = next_values
    for value in values:
        print(json.dumps(value) if isinstance(value, (bool, dict, list)) else value)
    sys.exit(0 if values else 1)

state_path = Path(os.environ["MOCK_STATE"])
state = json.loads(state_path.read_text())
method = args[args.index("-X") + 1]
url = next(arg for arg in args if arg.startswith("https://"))
path = urlparse(url).path
params = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "--data-urlencode")
body = json.loads(args[args.index("--data") + 1]) if "--data" in args else None
state["calls"].append({"method": method, "path": path, "params": params, "body": body})
response = {"success": True, "result": {}}
exit_code = 0
if state.get("fail_zone") and path.endswith("/zones"):
    response = {"success": False, "errors": [{"message": "simulated zone failure"}]}
elif state.get("fail_list") and method == "GET" and not path.endswith("/zones"):
    response = {"success": False, "errors": [{"message": "simulated list failure"}]}
elif path.endswith("/zones"):
    response["result"] = [{"id": "abcdef123456"}] if params["name"] in state["zones"] else []
elif method == "GET":
    assert params["match"] == "all"
    records = [r for r in state["records"] if r["name"] == params["name.exact"] and r["type"] == params["type"]]
    size = state.get("page_size", int(params["per_page"]))
    page = int(params["page"])
    response["result"] = records[(page - 1) * size:page * size]
    response["result_info"] = {"total_pages": math.ceil(len(records) / size)}
elif method == "POST":
    record = {**body, "id": "new-record"}
    state["records"].append(record)
    response["result"] = record
    if state.pop("lose_create_reply", False):
        exit_code = 28
elif method == "PUT":
    if state.get("fail_update"):
        response = {"success": False, "errors": [{"message": "simulated update failure"}]}
    else:
        record = next(r for r in state["records"] if r["id"] == path.split("/")[-1])
        record.update(body)
        response["result"] = record
elif method == "DELETE":
    if state.pop("fail_delete_once", False):
        response = {"success": False, "errors": [{"message": "simulated delete failure"}]}
    else:
        identifier = path.split("/")[-1]
        state["records"] = [r for r in state["records"] if r["id"] != identifier]
        response["result"] = {"id": identifier}
else:
    raise AssertionError(method)
state_path.write_text(json.dumps(state))
if exit_code:
    sys.exit(exit_code)
print(json.dumps(response))
'''


class CloudflareIP4PTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for tool in ["curl", "jsonfilter", "sleep"]:
            path = self.bin / tool
            path.write_text(f"#!{sys.executable}\n" + MOCK_TOOL)
            path.chmod(0o755)
        self.state_file = self.root / "state.json"
        self.env = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "MOCK_STATE": str(self.state_file),
            "TMPDIR": str(self.root),
            "CF_API_TOKEN": "test-token-not-a-real-credential",
            "DOMAIN": DOMAIN,
            "RECORD_TYPE": "AAAA",
            "PROXIED": "false",
            "TTL": "60",
        }

    def record(self, identifier, name=DOMAIN, record_type="AAAA"):
        return {"id": identifier, "name": name, "type": record_type, "content": "2001::1:c000:202"}

    def setup_state(self, records=(), **options):
        self.state_file.write_text(json.dumps({
            "records": list(records), "calls": [], "zones": ["example.com"], **options
        }))

    def state(self):
        return json.loads(self.state_file.read_text())

    def run_hook(self):
        return subprocess.run(["sh", str(HOOK), "unused", "unused", ADDRESS],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def assert_single_target(self):
        records = [r for r in self.state()["records"] if r["name"] == DOMAIN and r["type"] == "AAAA"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["content"], ADDRESS)
        self.assertFalse(records[0]["proxied"])

    def test_creates_one_record(self):
        self.setup_state()
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_single_target()

    def test_updates_before_deleting_duplicates_and_preserves_other_records(self):
        other = [self.record("other-name", "other.example.com"), self.record("other-type", record_type="A")]
        self.setup_state([self.record("first"), self.record("second"), *other])
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_single_target()
        self.assertTrue(all(record in self.state()["records"] for record in other))
        mutations = [c["method"] for c in self.state()["calls"] if c["method"] != "GET"]
        self.assertEqual(mutations, ["PUT", "DELETE"])

    def test_list_failure_never_creates_or_deletes(self):
        self.setup_state([self.record("first")], fail_list=True)
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertTrue(all(c["method"] == "GET" for c in self.state()["calls"]))

    def test_api_rejected_update_does_not_delete_valid_records(self):
        records = [self.record("first"), self.record("second")]
        self.setup_state(records, fail_update=True)
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertEqual(self.state()["records"], records)
        self.assertFalse(any(c["method"] == "DELETE" for c in self.state()["calls"]))

    def test_lost_create_reply_is_reconciled_without_second_post(self):
        self.setup_state(lose_create_reply=True)
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_single_target()
        self.assertEqual(sum(c["method"] == "POST" for c in self.state()["calls"]), 1)

    def test_pagination_and_partial_delete_failure(self):
        self.setup_state([self.record("first"), self.record("second"), self.record("third")],
                         page_size=1, fail_delete_once=True)
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_single_target()
        self.assertTrue(any(c["params"].get("page") == "3" for c in self.state()["calls"]))

    def test_discovers_multi_label_zone(self):
        self.setup_state(zones=["example.co.uk"])
        self.env["DOMAIN"] = "vpn.home.example.co.uk"
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        queries = [c["params"]["name"] for c in self.state()["calls"] if c["path"].endswith("/zones")]
        self.assertEqual(queries, ["vpn.home.example.co.uk", "home.example.co.uk", "example.co.uk"])
        self.assertEqual(self.state()["records"][0]["name"], self.env["DOMAIN"])

    def test_uses_closest_accessible_zone(self):
        self.setup_state(zones=[DOMAIN, "example.com"])
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        queries = [c["params"]["name"] for c in self.state()["calls"] if c["path"].endswith("/zones")]
        self.assertEqual(queries, [DOMAIN])

    def test_missing_zone_stops_without_modifying_records(self):
        self.setup_state(zones=[])
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No accessible active Cloudflare zone", result.stderr)
        self.assertEqual([c["params"]["name"] for c in self.state()["calls"]], [DOMAIN, "example.com"])
        self.assertTrue(all(c["method"] == "GET" for c in self.state()["calls"]))

    def test_zone_query_failure_stops_without_parent_fallback(self):
        self.setup_state(fail_zone=True)
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertEqual(len(self.state()["calls"]), 1)
        self.assertEqual(self.state()["calls"][0]["method"], "GET")

    def test_proxied_mode_is_rejected_before_network_access(self):
        self.setup_state()
        self.env["PROXIED"] = "true"
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertEqual(self.state()["calls"], [])


if __name__ == "__main__":
    unittest.main()
