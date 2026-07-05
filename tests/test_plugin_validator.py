import unittest

from modules import plugin_validator


class PluginValidatorTests(unittest.TestCase):
    def test_hand_authored_template_passes(self):
        code = (
            "from modules.plugins import ScanPlugin\n"
            "\n"
            "class ExampleScan(ScanPlugin):\n"
            "    name = 'example_scan'\n"
            "    def should_run(self, host, port, port_data):\n"
            "        return port == 1234\n"
            "    def run(self, host, port, port_data):\n"
            "        return {'status': 'ok'}\n"
        )
        result = plugin_validator.validate(code)
        self.assertTrue(result.ok, result.errors)

    def test_quarantined_ai_gen_ssh_plugin_passes(self):
        code = (
            "from modules.plugins import ScanPlugin\n"
            "\n"
            "class Ssh22Scan(ScanPlugin):\n"
            "    name = 'ssh_22'\n"
            "    def should_run(self, host, port, port_data):\n"
            "        return port == 22 or port_data.get('service') == 'ssh'\n"
            "    def run(self, host, port, port_data):\n"
            "        return {'banner': port_data.get('banner')}\n"
        )
        result = plugin_validator.validate(code)
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
