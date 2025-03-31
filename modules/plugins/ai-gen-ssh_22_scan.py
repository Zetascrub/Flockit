from modules.plugins import ScanPlugin
from utils.common import print_status
import socket


from modules.plugins import ScanPlugin
import socket

class Ssh_22Scan(ScanPlugin):
    name = "ssh_22"

    def should_run(self, host, port, port_data):
        """Check if the plugin should run for a given host and port."""
        return port == 22

    def run(self, host, port, port_data):
        """Run the SSH-22 scan on a given host and port."""
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to the server on the specified port
            sock.connect((host, port))
            
            # Get the banner from the server
            banner = sock.recv(1024).decode()
            
            # Close the socket
            sock.close()
        except Exception as e:
            print_status(f"Failed to connect to {host}:{port} - {e}")
            return {"status": "failed"}
        
        # If we reach this point, it means the connection was successful
        print_status(f"Connected to {host}:{port}.")
        return {"banner": banner}