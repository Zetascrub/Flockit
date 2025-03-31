import os
import importlib.util
import re
import sys
import inspect
from utils.common import print_status, ollama_chat
from modules.plugins import ScanPlugin
import textwrap

class Magpie:
    def __init__(self, plugin_dir="modules/plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = []
        self.load_plugins()

    def load_plugins(self):
        if not os.path.exists(self.plugin_dir):
            print_status(f"Plugin folder '{self.plugin_dir}' does not exist.", "error")
            return

        sys.path.insert(0, self.plugin_dir)
        for filename in os.listdir(self.plugin_dir):
            if not filename.endswith(".py") or filename.startswith("__"):
                continue

            plugin_path = os.path.join(self.plugin_dir, filename)
            module_name = filename[:-3]

            try:
                spec = importlib.util.spec_from_file_location(module_name, plugin_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, ScanPlugin) and obj is not ScanPlugin:
                        plugin_instance = obj()

                        class_label = obj.__name__
                        plugin_name = getattr(plugin_instance, "name", None)

                        if not plugin_name:
                            plugin_name = class_label
                            print_status(
                                f"[!] Plugin {class_label} missing 'name' attribute. Using class name fallback.",
                                "warning")

                        file_label = os.path.basename(filename)

                        print_status(
                            f"[+] Registered plugin: {plugin_name} (class: {class_label}, file: {file_label})",
                            "info"
                        )
                        self.plugins.append(plugin_instance)

            except Exception as e:
                print_status(f"[-] Failed to load plugin from {filename}: {e}", "error")

    def get_plugins(self):
        return self.plugins

    def is_port_covered(self, port_data):
        for plugin in self.plugins:
            if plugin.should_run("dummyhost", port_data["port"], port_data):
                return True
        return False

    def generate_plugin_for(self, port_data):
        port = port_data['port']
        service = port_data.get('service', 'unknown').replace("-", "_")
        version = port_data.get('version', '')
        banner = port_data.get('banner', '')

        plugin_slug = f"{service}_{port}".replace("-", "_").lower()
        class_name = f"{plugin_slug.capitalize()}Scan"
        plugin_filename = f"ai-gen-{plugin_slug}_scan.py"
        plugin_path = os.path.join(self.plugin_dir, plugin_filename)

        if os.path.exists(plugin_path):
            print_status(f"[!] Plugin file {plugin_filename} already exists. Skipping generation.", "warning")
            return
        print_status(f"Attempting to generate a new plugin for {service}:{port}", "info")

        system_prompt = (
            "You are a cybersecurity plugin generator. Your job is to write a Python class that inherits "
            "from `ScanPlugin`. The plugin should detect or extract information from a specific network service "
            "running on a given port. Keep the code readable and efficient. Do not use __init__."
        )

        user_prompt = f"""
    Write a Python plugin class for a network scanner tool.

    Requirements:
    - Inherit from `ScanPlugin` (from `modules.plugins`)
    - Class name: `{class_name}`
    - Set class attribute `name = "{plugin_slug}"`
    - Implement two methods:
      - `should_run(self, host, port, port_data)` — should return True when port == {port}
      - `run(self, host, port, port_data)` — must:
          - use `socket` if applicable,
          - call `print_status(...)` from `utils.common`,
          - return a `dict` like: `{{ "banner": banner }}` or `{{ "status": "ok" }}`

    Rules:
    - ❌ DO NOT include an `__init__` method
    - ✅ `run()` must return a dictionary
    - ✅ Use meaningful return keys like "banner", "status", or "details"
    """

        for attempt in range(3):
            plugin_body_raw = ollama_chat(system_prompt, user_prompt)

            if "```" not in plugin_body_raw and "class" not in plugin_body_raw:
                print_status(f"[!] AI response did not return valid code. Skipping plugin generation for: {service}",
                             "warning")
                return

            plugin_body = extract_python_code(plugin_body_raw)

            # Fix common import errors
            plugin_body = plugin_body.replace("from utils.common import ScanPlugin",
                                              "from modules.plugins import ScanPlugin")
            plugin_body = plugin_body.replace("from modules.utils import common", "from utils import common")
            plugin_body = plugin_body.replace("from modules.utils.common import print_status",
                                              "from utils.common import print_status")
            plugin_body = plugin_body.replace("print_error", "print_status")

            if validate_plugin_code(plugin_body):
                break
            else:
                print_status(
                    f"[!] Attempt {attempt + 1}: Generated plugin for {service} failed validation. Retrying...",
                    "warning")
        else:
            print_status(f"[!] Final attempt failed. Plugin for {service} not saved.", "warning")
            return

        # Prepend fallback header in case LLM omits it
        header = textwrap.dedent(f"""
            from modules.plugins import ScanPlugin
            from utils.common import print_status
            import socket
        """)

        full_code = header + "\n\n" + plugin_body

        # Remove any duplicate imports
        lines = full_code.splitlines()
        seen = set()
        cleaned_lines = []
        for line in lines:
            if line.strip().startswith("from ") or line.strip().startswith("import "):
                if line in seen:
                    continue
                seen.add(line)
            cleaned_lines.append(line)
        full_code = "\n".join(cleaned_lines)

        with open(plugin_path, "w", encoding="utf-8") as f:
            f.write(full_code.strip())

        print_status(f"[+] Generated new AI plugin: {plugin_filename}", "success")


def extract_python_code(ollama_response: str) -> str:
    """
    Extracts the first Python code block from an Ollama markdown response.
    If no code block is found, returns the original string.
    """
    code_blocks = re.findall(r"```(?:python)?\n(.*?)```", ollama_response, re.DOTALL)
    return code_blocks[0].strip() if code_blocks else ollama_response.strip()

def validate_plugin_code(code: str) -> bool:
    """
    Validates AI-generated plugin code by checking for common issues like dangerous __init__ methods,
    missing required methods, and improper return handling in run().
    """
    valid = True

    # 1. Check for incorrect import
    if "from utils.common import ScanPlugin" in code:
        print_status("[!] Plugin has invalid import for ScanPlugin", "warning")
        valid = False

    # 2. Check for risky or unnecessary __init__
    if "def __init__" in code:
        if "super().__init__" not in code:
            print_status("[!] Plugin defines a risky __init__ (no super()). Skipping.", "warning")
            valid = False
        elif "__init__" in code and "self.name" not in code:
            print_status("[!] Plugin __init__ exists but doesn't appear necessary. Skipping.", "warning")
            valid = False

    # 3. Must define should_run and run
    if "def should_run" not in code:
        print_status("[!] Plugin missing required method: should_run()", "warning")
        valid = False
    if "def run" not in code:
        print_status("[!] Plugin missing required method: run()", "warning")
        valid = False

    # 4. run() should return something
    if "def run" in code:
        run_section = code.split("def run", 1)[1]
        if "return" not in run_section:
            print_status("[!] Plugin run() method does not contain a return statement", "warning")
            valid = False

    # 5. Bonus check: must return a dictionary or string, not just log output
    if "return {" not in code and "return \"" not in code and "return '" not in code:
        print_status("[!] Plugin run() does not appear to return useful data (dictionary or string)", "warning")
        valid = False

    return valid

