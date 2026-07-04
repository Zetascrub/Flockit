import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from modules.plugin_manager import PluginManager

GOOD_PLUGIN_RESPONSE = (
    "```python\n"
    "class Http8081Scan(ScanPlugin):\n"
    "    name = \"http_8081\"\n"
    "    def should_run(self, host, port, port_data):\n"
    "        return port == 8081\n"
    "    def run(self, host, port, port_data):\n"
    "        return {\"status\": \"ok\"}\n"
    "```"
)

BAD_PLUGIN_RESPONSE = (
    "```python\n"
    "import os\n"
    "class BadScan(ScanPlugin):\n"
    "    def should_run(self, host, port, port_data):\n"
    "        return True\n"
    "    def run(self, host, port, port_data):\n"
    "        return {}\n"
    "```"
)


def make_ai_client(response_text):
    ai_client = MagicMock()
    ai_client.config.provider = "ollama"
    ai_client.chat.return_value = response_text
    return ai_client


class PluginManagerQuarantineTests(unittest.TestCase):
    def test_generate_plugin_for_writes_only_to_quarantine(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trusted_dir = os.path.join(tmpdir, "plugins")
            quarantine_dir = os.path.join(tmpdir, "plugins_quarantine")
            os.makedirs(trusted_dir)

            plugin_manager = PluginManager(plugin_dir=trusted_dir, quarantine_dir=quarantine_dir)
            ai_client = make_ai_client(GOOD_PLUGIN_RESPONSE)

            filename = plugin_manager.generate_plugin_for({"port": 8081, "service": "http", "version": "", "banner": ""}, ai_client)

            self.assertIsNotNone(filename)
            self.assertTrue(os.path.exists(os.path.join(quarantine_dir, filename)))
            self.assertFalse(os.path.exists(os.path.join(trusted_dir, filename)))

            with open(os.path.join(quarantine_dir, filename + ".meta.json")) as f:
                meta = json.load(f)
            self.assertEqual(meta["status"], "pending")

            # A fresh PluginManager loading only from the trusted dir must not see it.
            reload_plugin_manager = PluginManager(plugin_dir=trusted_dir, quarantine_dir=quarantine_dir)
            self.assertEqual(reload_plugin_manager.plugins, [])

    def test_generate_plugin_for_marks_invalid_code_as_invalid_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trusted_dir = os.path.join(tmpdir, "plugins")
            quarantine_dir = os.path.join(tmpdir, "plugins_quarantine")
            os.makedirs(trusted_dir)

            plugin_manager = PluginManager(plugin_dir=trusted_dir, quarantine_dir=quarantine_dir)
            ai_client = make_ai_client(BAD_PLUGIN_RESPONSE)

            filename = plugin_manager.generate_plugin_for({"port": 9999, "service": "weird", "version": "", "banner": ""}, ai_client)

            with open(os.path.join(quarantine_dir, filename + ".meta.json")) as f:
                meta = json.load(f)
            self.assertEqual(meta["status"], "invalid")
            self.assertTrue(meta["validation_errors"])

    def test_does_not_regenerate_if_already_quarantined(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            trusted_dir = os.path.join(tmpdir, "plugins")
            quarantine_dir = os.path.join(tmpdir, "plugins_quarantine")
            os.makedirs(trusted_dir)

            plugin_manager = PluginManager(plugin_dir=trusted_dir, quarantine_dir=quarantine_dir)
            ai_client = make_ai_client(GOOD_PLUGIN_RESPONSE)

            port_data = {"port": 8081, "service": "http", "version": "", "banner": ""}
            first = plugin_manager.generate_plugin_for(port_data, ai_client)
            second = plugin_manager.generate_plugin_for(port_data, ai_client)

            self.assertIsNotNone(first)
            self.assertIsNone(second)
            self.assertEqual(ai_client.chat.call_count, 1)


if __name__ == "__main__":
    unittest.main()
