# --- Plugin Class ---
class ScanPlugin:
    """
    Base class for scan plugins.
    Each plugin should define a unique name, a condition (should_run) and execution logic (run).
    """
    name = "base_plugin"

    def should_run(self, host, port, port_data):
        return False

    def run(self, host, port, port_data):
        return None