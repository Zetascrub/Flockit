from modules.plugins import ScanPlugin
from utils.common import print_status
import socket


from modules.plugins import ScanPlugin
import socket

class Http_80Scan(ScanPlugin):
    name = "http_80"

    def should_run(self, host, port, port_data):
        """Return True if the port is 80."""
        return int(port) == 80

    def run(self, host, port, port_data):
        """Run the HTTP 80 scan and print status."""
        
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Attempt to connect to the target host on the specified port
        try:
            sock.connect((host, int(port)))
            
            # If connection is successful, get the banner from the server
            banner = sock.recv(1024).decode()
            
            # Print the status and close the socket
            self.print_status("ok", "HTTP 80 scan successful.")
            sock.close()
            
            # Return a dictionary with the banner
            return {"banner": banner}
        
        except ConnectionRefusedError:
            # If connection is refused, print an error message and close the socket
            self.print_status("error", "Connection to {} on port {} was refused.".format(host, int(port)))
            sock.close()
            
            # Return a dictionary with the status
            return {"status": "error"}
        
        except Exception as e:
            # If any other exception occurs, print an error message and close the socket
            self.print_status("error", str(e))
            sock.close()
            
            # Return a dictionary with the status
            return {"status": "error"}