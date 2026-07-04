import json
import os
import tempfile
import unittest

from modules import plugin_manager

PLUGIN_CODE = (
    "from modules.plugins import ScanPlugin\n"
    "class TestScan(ScanPlugin):\n"
    "    name = \"test_1234\"\n"
    "    def should_run(self, host, port, port_data):\n"
    "        return port == 1234\n"
    "    def run(self, host, port, port_data):\n"
    "        return {\"status\": \"ok\"}\n"
)


class PluginLifecycleTests(unittest.TestCase):
    def _seed_quarantine(self, quarantine_dir, filename="ai-gen-test_1234_scan.py", status="pending", code=PLUGIN_CODE):
        os.makedirs(quarantine_dir, exist_ok=True)
        with open(os.path.join(quarantine_dir, filename), "w") as f:
            f.write(code)
        meta = {
            "generated_at": "2026-01-01T00:00:00",
            "port": 1234,
            "service": "test",
            "provider": "ollama",
            "status": status,
            "validation_errors": [],
        }
        with open(os.path.join(quarantine_dir, filename + ".meta.json"), "w") as f:
            json.dump(meta, f)
        return filename

    def test_list_quarantined_reads_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            quarantine_dir = os.path.join(tmpdir, "quarantine")
            filename = self._seed_quarantine(quarantine_dir)

            entries = plugin_manager.list_quarantined(quarantine_dir)

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["filename"], filename)
            self.assertEqual(entries[0]["status"], "pending")

    def test_approve_moves_file_into_trusted_dir_and_becomes_loadable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            quarantine_dir = os.path.join(tmpdir, "quarantine")
            trusted_dir = os.path.join(tmpdir, "trusted")
            filename = self._seed_quarantine(quarantine_dir)

            result = plugin_manager.approve_quarantined(filename, quarantine_dir, trusted_dir)

            self.assertTrue(result)
            self.assertTrue(os.path.exists(os.path.join(trusted_dir, filename)))
            self.assertFalse(os.path.exists(os.path.join(quarantine_dir, filename)))

            loaded = plugin_manager.PluginManager(plugin_dir=trusted_dir, quarantine_dir=quarantine_dir)
            self.assertEqual(len(loaded.plugins), 1)
            self.assertEqual(loaded.plugins[0].name, "test_1234")

    def test_approve_refuses_invalid_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            quarantine_dir = os.path.join(tmpdir, "quarantine")
            trusted_dir = os.path.join(tmpdir, "trusted")
            filename = self._seed_quarantine(
                quarantine_dir, filename="ai-gen-bad_1234_scan.py", status="invalid",
                code="import os\nclass Bad:\n    pass\n",
            )

            result = plugin_manager.approve_quarantined(filename, quarantine_dir, trusted_dir)

            self.assertFalse(result)
            self.assertFalse(os.path.exists(os.path.join(trusted_dir, filename)))
            self.assertTrue(os.path.exists(os.path.join(quarantine_dir, filename)))  # left in place

    def test_reject_moves_file_to_rejected_subdir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            quarantine_dir = os.path.join(tmpdir, "quarantine")
            filename = self._seed_quarantine(quarantine_dir)

            result = plugin_manager.reject_quarantined(filename, quarantine_dir)

            self.assertTrue(result)
            self.assertTrue(os.path.exists(os.path.join(quarantine_dir, "rejected", filename)))
            self.assertFalse(os.path.exists(os.path.join(quarantine_dir, filename)))

            with open(os.path.join(quarantine_dir, "rejected", filename + ".meta.json")) as f:
                meta = json.load(f)
            self.assertEqual(meta["status"], "rejected")

    def test_approve_missing_file_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            quarantine_dir = os.path.join(tmpdir, "quarantine")
            trusted_dir = os.path.join(tmpdir, "trusted")
            os.makedirs(quarantine_dir)

            result = plugin_manager.approve_quarantined("does-not-exist.py", quarantine_dir, trusted_dir)

            self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
