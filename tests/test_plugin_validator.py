import os
import unittest

from modules import plugin_validator

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(relative_path):
    with open(os.path.join(REPO_ROOT, relative_path), encoding="utf-8") as f:
        return f.read()


class PluginValidatorTests(unittest.TestCase):
    def test_hand_authored_template_passes(self):
        result = plugin_validator.validate(read("Plugin_Dev/plugin_template.py"))
        self.assertTrue(result.ok, result.errors)

    def test_quarantined_ai_gen_ssh_plugin_passes(self):
        result = plugin_validator.validate(read("modules/plugins_quarantine/ai-gen-ssh_22_scan.py"))
        self.assertTrue(result.ok, result.errors)

    def test_disallowed_import_fails(self):
        code = (
            "import os\n"
            "from modules.plugins import ScanPlugin\n"
            "class X(ScanPlugin):\n"
            "    def should_run(self, host, port, port_data):\n"
            "        return True\n"
            "    def run(self, host, port, port_data):\n"
            "        return {}\n"
        )
        result = plugin_validator.validate(code)
        self.assertFalse(result.ok)
        self.assertTrue(any("os" in e for e in result.errors))

    def test_disallowed_import_from_fails(self):
        code = (
            "from subprocess import run as sub_run\n"
            "from modules.plugins import ScanPlugin\n"
            "class X(ScanPlugin):\n"
            "    def should_run(self, host, port, port_data):\n"
            "        return True\n"
            "    def run(self, host, port, port_data):\n"
            "        return {}\n"
        )
        result = plugin_validator.validate(code)
        self.assertFalse(result.ok)

    def test_eval_call_fails(self):
        code = (
            "from modules.plugins import ScanPlugin\n"
            "class X(ScanPlugin):\n"
            "    def should_run(self, host, port, port_data):\n"
            "        return eval('True')\n"
            "    def run(self, host, port, port_data):\n"
            "        return {}\n"
        )
        result = plugin_validator.validate(code)
        self.assertFalse(result.ok)
        self.assertTrue(any("eval" in e for e in result.errors))

    def test_missing_run_method_fails(self):
        code = (
            "from modules.plugins import ScanPlugin\n"
            "class X(ScanPlugin):\n"
            "    def should_run(self, host, port, port_data):\n"
            "        return True\n"
        )
        result = plugin_validator.validate(code)
        self.assertFalse(result.ok)
        self.assertTrue(any("run" in e for e in result.errors))

    def test_init_method_fails(self):
        code = (
            "from modules.plugins import ScanPlugin\n"
            "class X(ScanPlugin):\n"
            "    def __init__(self):\n"
            "        pass\n"
            "    def should_run(self, host, port, port_data):\n"
            "        return True\n"
            "    def run(self, host, port, port_data):\n"
            "        return {}\n"
        )
        result = plugin_validator.validate(code)
        self.assertFalse(result.ok)
        self.assertTrue(any("__init__" in e for e in result.errors))

    def test_syntax_error_fails(self):
        result = plugin_validator.validate("class X(:\n    broken")
        self.assertFalse(result.ok)
        self.assertTrue(any("syntax error" in e for e in result.errors))

    def test_no_scan_plugin_subclass_fails(self):
        code = "class NotAPlugin:\n    def should_run(self, h, p, d):\n        return True\n    def run(self, h, p, d):\n        return {}\n"
        result = plugin_validator.validate(code)
        self.assertFalse(result.ok)
        self.assertTrue(any("ScanPlugin" in e for e in result.errors))


if __name__ == "__main__":
    unittest.main()
