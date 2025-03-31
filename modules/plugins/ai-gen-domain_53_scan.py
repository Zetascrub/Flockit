from modules.plugins import ScanPlugin
from utils.common import print_status
import socket


from modules.plugins import ScanPlugin
import socket
from utils.common import print_status

class Domain_53Scan(ScanPlugin):
    name = "domain_53"

    def should_run(self, host, port, port_data):
        """
        Determine if this plugin should run on the given host and port.

        Args:
            host (str): The hostname or IP address to scan.
            port (int): The port number to check.
            port_data: Additional information about the port, such as its name.

        Returns:
            bool: True if the plugin should run, False otherwise.
        """
        return port == 53

    def run(self, host, port, port_data):
        """
        Run the scan and retrieve the banner for the given port.

        Args:
            host (str): The hostname or IP address to scan.
            port (int): The port number to check.
            port_data: Additional information about the port, such as its name.

        Returns:
            dict: A dictionary containing the scan results. Must include a "banner" key with the banner text.
        """
        try:
            # Create a socket object to connect to the domain 53 service
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            # Try to establish a connection
            sock.connect((host, port))

            # Read data from the server (the banner) and store it in the result dictionary
            data = sock.recv(1024)
            banner = data.decode().strip()

            # Close the socket
            sock.close()

            return {"banner": banner}

        except Exception as e:
            print_status("Error scanning port {}: {}".format(port, str(e),"warning"))
            return {}

        finally:
            # If an exception occurs, print a status message and return an empty dictionary
            if hasattr(self, 'print_status'):
                self.print_status("Error scanning port {}: {}".format(port, "Unknown error"))