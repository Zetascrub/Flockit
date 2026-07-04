class ScanPlugin:
    """
    Base class for scan plugins.
    Each plugin should define a unique name, a condition (should_run) and execution logic (run).

    run() may optionally include these keys in its returned dict to influence
    adaptive scan escalation (see modules/adaptive.py); absence means "no opinion"
    and is fully backward compatible with existing plugins:
      - "escalate": bool — vote to escalate this host to a deeper scan
      - "escalate_weight": int — score contribution if escalate is True (default 2)
      - "escalate_reason": str — human-readable reason shown in the report
    """
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
