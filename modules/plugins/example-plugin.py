try:
    from modules.plugins import ScanPlugin  # Core file defines base class
except ImportError:
    from __main__ import ScanPlugin

import socket
from util import print_status

class MyCustomPlugin(ScanPlugin):
    """
    Example Plugin Template
    -----------------------
    Use this as a base for writing your own scanning plugin.

    Attributes:
        name (str): A unique name for this plugin.
    """
    name = "my_custom_plugin"

    def should_run(self, host, port, port_data):
        """
        Define the condition under which the plugin should run.

        Args:
            host (str): IP or hostname.
            port (int): Port number.
            port_data (dict): Metadata from the scanner (state, service, etc.).

        Returns:
            bool: True if plugin should run; False otherwise.
        """
        return port == 8080  # Example: only run on port 8080

    def run(self, host, port, port_data):
        """
        Execute your scanning logic.

        Returns:
            str: Summary of results or error message.
        """
        try:
            print_status(f"Plugin - Running {name} against {host}:{port}...", "scan")
            with socket.create_connection((host, port), timeout=5) as s:
                s.sendall(b"YOUR CUSTOM REQUEST\r\n")
                response = s.recv(1024).decode("utf-8", "ignore")
                banner = response.strip().split("\n")[0]
                print_status(f"[MyCustomPlugin] Response: {banner}", "success")
                return banner
        except Exception as e:
            print_status(f"[MyCustomPlugin] Error: {e}", "warning")
            return f"Error: {e}"
