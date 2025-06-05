class ScanPlugin:
    """Base class for all scanning plugins."""

    # Short unique plugin name
    name = "base_plugin"
    # Optional semantic version
    version = 1
    # Human readable description
    description = ""

    def should_run(self, host, port, port_data):
        """Return True if plugin should execute for this port."""
        return False

    def run(self, host, port, port_data):
        """Execute plugin logic and return a result dictionary."""
        return {}
