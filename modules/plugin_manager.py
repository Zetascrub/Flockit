import importlib.util
import inspect
import json
import os
import shutil
import sys
from datetime import datetime

from modules import ai_prompts, plugin_validator
from modules.plugins import ScanPlugin
from utils.common import print_status

DEFAULT_PLUGIN_DIR = "modules/plugins"
DEFAULT_QUARANTINE_DIR = "modules/plugins_quarantine"


class PluginManager:
    def __init__(self, plugin_dir=DEFAULT_PLUGIN_DIR, quarantine_dir=DEFAULT_QUARANTINE_DIR):
        self.plugin_dir = plugin_dir
        self.quarantine_dir = quarantine_dir
        self.plugins = []
        self.load_plugins()

    def load_plugins(self):
        """Only ever imports from the trusted plugin_dir. Quarantined
        candidates (see generate_plugin_for) are never on this import path,
        regardless of automation settings — they require explicit approval
        via approve_quarantined()/`sift.py plugins approve` first."""
        if not os.path.exists(self.plugin_dir):
            print_status(f"Plugin folder '{self.plugin_dir}' does not exist.", "error")
            return

        if self.plugin_dir not in sys.path:
            sys.path.insert(0, self.plugin_dir)
        loaded_names = {getattr(plugin, "name", plugin.__class__.__name__) for plugin in self.plugins}
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

                        if not plugin_name or plugin_name == ScanPlugin.name:
                            plugin_name = class_label
                            plugin_instance.name = plugin_name
                            print_status(
                                f"[!] Plugin {class_label} missing unique 'name' attribute. Using class name fallback.",
                                "warning")

                        if plugin_name in loaded_names:
                            print_status(f"[!] Duplicate plugin name '{plugin_name}' from {filename}. Skipping.", "warning")
                            continue

                        file_label = os.path.basename(filename)

                        print_status(
                            f"[+] Registered plugin: {plugin_name} (class: {class_label}, file: {file_label})",
                            "info"
                        )
                        self.plugins.append(plugin_instance)
                        loaded_names.add(plugin_name)

            except Exception as e:
                print_status(f"[-] Failed to load plugin from {filename}: {e}", "error")

    def get_plugins(self):
        return self.plugins

    def is_port_covered(self, port_data):
        for plugin in self.plugins:
            if plugin.should_run("dummyhost", port_data["port"], port_data):
                return True
        return False

    def generate_plugin_for(self, port_data, ai_client):
        """Generates a candidate plugin and writes it to the quarantine
        directory only — never into the trusted plugin_dir. The candidate
        requires an explicit `sift.py plugins approve <file>` (which
        re-validates before moving it) to become part of the trusted,
        auto-loaded runtime path."""
        port = port_data["port"]
        service = (port_data.get("service") or "unknown").replace("-", "_")
        plugin_slug = f"{service}_{port}".replace("-", "_").lower()
        plugin_filename = f"ai-gen-{plugin_slug}_scan.py"

        quarantine_path = os.path.join(self.quarantine_dir, plugin_filename)
        trusted_path = os.path.join(self.plugin_dir, plugin_filename)
        if os.path.exists(quarantine_path) or os.path.exists(trusted_path):
            print_status(f"[!] Plugin file {plugin_filename} already exists (quarantined or trusted). Skipping generation.", "warning")
            return None

        print_status(f"Attempting to generate a new plugin for {service}:{port}", "info")

        code = ai_prompts.generate_plugin_code(port_data, ai_client)
        if not code or "class" not in code:
            print_status(f"[!] AI response did not return valid code. Skipping plugin generation for: {service}", "warning")
            return None

        header = "from modules.plugins import ScanPlugin\nfrom utils.common import print_status\nimport socket\n\n\n"
        full_code = header + code

        validation = plugin_validator.validate(full_code)

        os.makedirs(self.quarantine_dir, exist_ok=True)
        with open(quarantine_path, "w") as f:
            f.write(full_code)

        meta = {
            "generated_at": datetime.now().isoformat(),
            "port": port,
            "service": service,
            "provider": ai_client.config.provider,
            "status": "pending" if validation.ok else "invalid",
            "validation_errors": validation.errors,
        }
        with open(quarantine_path + ".meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        if validation.ok:
            print_status(
                f"[+] Generated candidate plugin {plugin_filename} (validation: ok) — "
                f"review with `sift.py plugins show {plugin_filename}` before it can run.",
                "success",
            )
        else:
            print_status(
                f"[!] Generated candidate plugin {plugin_filename} failed validation "
                f"({len(validation.errors)} error(s)): {validation.errors}",
                "warning",
            )

        return plugin_filename


# --- Quarantine lifecycle helpers, used by the `sift.py plugins` CLI ---

def list_quarantined(quarantine_dir=DEFAULT_QUARANTINE_DIR):
    if not os.path.isdir(quarantine_dir):
        return []
    entries = []
    for filename in sorted(os.listdir(quarantine_dir)):
        if not filename.endswith(".py"):
            continue
        entries.append({"filename": filename, **_read_meta(quarantine_dir, filename)})
    return entries


def read_quarantined_source(quarantine_dir, filename):
    path = os.path.join(quarantine_dir, filename)
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return f.read()


def _read_meta(directory, filename):
    meta_path = os.path.join(directory, filename + ".meta.json")
    if not os.path.exists(meta_path):
        return {}
    with open(meta_path) as f:
        return json.load(f)


def approve_quarantined(filename, quarantine_dir=DEFAULT_QUARANTINE_DIR, trusted_dir=DEFAULT_PLUGIN_DIR):
    """Re-validates (in case the file was hand-edited since generation) before
    moving it into the trusted, auto-loaded plugin directory."""
    src_path = os.path.join(quarantine_dir, filename)
    if not os.path.isfile(src_path):
        print_status(f"[-] {filename} not found in quarantine.", "error")
        return False

    with open(src_path) as f:
        code = f.read()
    validation = plugin_validator.validate(code)
    if not validation.ok:
        print_status(f"[-] {filename} still fails validation, refusing to approve: {validation.errors}", "error")
        return False

    os.makedirs(trusted_dir, exist_ok=True)
    dest_path = os.path.join(trusted_dir, filename)
    shutil.move(src_path, dest_path)

    meta = _read_meta(quarantine_dir, filename)
    meta_src = src_path + ".meta.json"
    if os.path.exists(meta_src):
        os.remove(meta_src)
    meta["status"] = "approved"
    with open(dest_path + ".meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print_status(f"[+] Approved {filename} — it will load on the next run.", "success")
    return True


def reject_quarantined(filename, quarantine_dir=DEFAULT_QUARANTINE_DIR):
    src_path = os.path.join(quarantine_dir, filename)
    if not os.path.isfile(src_path):
        print_status(f"[-] {filename} not found in quarantine.", "error")
        return False

    rejected_dir = os.path.join(quarantine_dir, "rejected")
    os.makedirs(rejected_dir, exist_ok=True)
    dest_path = os.path.join(rejected_dir, filename)
    shutil.move(src_path, dest_path)

    meta = _read_meta(quarantine_dir, filename)
    meta_src = src_path + ".meta.json"
    if os.path.exists(meta_src):
        os.remove(meta_src)
    meta["status"] = "rejected"
    with open(dest_path + ".meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print_status(f"[+] Rejected {filename}.", "info")
    return True
