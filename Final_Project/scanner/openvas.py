import os
import xml.etree.ElementTree as ET
from dotenv import load_dotenv

# Optional import for the actual GVM tools connection (python-gvm library)
# If python-gvm is not installed, the class will still provide the boilerplate structure.
try:
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    from gvm.errors import GvmError
    HAS_GVM = True
except ImportError:
    HAS_GVM = False

load_dotenv()

OPENVAS_HOST = os.getenv("OPENVAS_HOST", "127.0.0.1")
OPENVAS_PORT = int(os.getenv("OPENVAS_PORT", 9390))
OPENVAS_USER = os.getenv("OPENVAS_USER", "admin")
OPENVAS_PASS = os.getenv("OPENVAS_PASS", "admin")


class OpenVASScanner:
    """
    Boilerplate for connecting to Greenbone Vulnerability Management (GVM) daemon.
    Allows creating targets, starting tasks, and parsing XML reports.
    Requires python-gvm to be fully operational.
    """
    
    def __init__(self, use_tls=True):
        self.use_tls = use_tls
        self.gmp = None
        self.connection = None

    def connect(self):
        """Initializes connection to the GVM daemon via TCP/TLS or Unix Socket."""
        if not HAS_GVM:
            return {"error": "python-gvm library is not installed."}
            
        try:
            if self.use_tls:
                # Typical remote GVM connection
                self.connection = TLSConnection(hostname=OPENVAS_HOST, port=OPENVAS_PORT)
            else:
                # Local connection usually via gvmd socket
                self.connection = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
                
            transform = EtreeTransform()
            self.gmp = Gmp(connection=self.connection, transform=transform)
            
            # Authenticate
            self.gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)
            return {"status": "connected"}
            
        except Exception as e:
            return {"error": f"Connection failed: {str(e)}"}

    def get_version(self):
        """Fetches the GMP version of the OpenVAS server."""
        if not self.gmp:
            return "Not connected"
        try:
            version = self.gmp.get_version()
            return version.get('version', 'Unknown')
        except Exception as e:
            return str(e)

    def create_target_and_scan(self, ip_address: str, task_name: str):
        """
        Creates a new target for the IP and attaches it to a scanning task.
        (Uses standard OpenVAS pre-defined 'Full and fast' config)
        """
        if not self.gmp:
            return {"error": "Not connected"}
            
        try:
            # Create Target
            target_id = self.gmp.create_target(
                name=f"Target: {ip_address}",
                hosts=[ip_address],
                port_list_id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5" # All IANA assigned TCP
            ).get('id')
            
            # Create Task
            config_id = "daba56c8-73ec-11df-a475-002264764cea" # Full and fast config
            task_id = self.gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id="08b69003-5fc2-4037-a479-93b440211c73" # OpenVAS Default
            ).get('id')
            
            # Start Task
            report_id = self.gmp.start_task(task_id).find('report_id').text
            
            return {
                "status": "scan_started", 
                "task_id": task_id, 
                "report_id": report_id
            }
        except Exception as e:
            return {"error": str(e)}

    def disconnect(self):
        """Gracefully close the GVM connection."""
        if self.connection:
            self.connection.disconnect()


if __name__ == "__main__":
    scanner = OpenVASScanner()
    print("[*] OpenVAS Boilerplate Initialized.")
    if HAS_GVM:
        print("[*] python-gvm library found.")
    else:
        print("[!] python-gvm not found. Run: pip install python-gvm")
