\"\"\"
ARP Spoofing Detection Module
\"\"\"

from typing import Dict, List, Optional, Callable
from scapy.all import sniff, ARP, conf
from collections import defaultdict
import time
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

class ARPDetector:
    \"\"\"Detects ARP spoofing attacks.\"\"\"
    
    def __init__(self, interface: Optional[str] = None, alert_callback: Optional[Callable] = None):
        self.interface = interface or conf.iface
        self.alert_callback = alert_callback
        self.arp_table: Dict[str, str] = {}
        self.ip_mac_pairs: Dict[str, List[str]] = defaultdict(list)
        self.is_monitoring = False
        logger.info(f"ARP Detector initialized on interface {self.interface}")
    
    def _packet_handler(self, packet) -> None:
        if ARP in packet and packet[ARP].op == 2:
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            if src_ip in self.arp_table:
                known_mac = self.arp_table[src_ip]
                if known_mac != src_mac:
                    self._alert_spoofing(src_ip, known_mac, src_mac)
            else:
                self.arp_table[src_ip] = src_mac
            
            if src_mac not in self.ip_mac_pairs[src_ip]:
                self.ip_mac_pairs[src_ip].append(src_mac)
                if len(self.ip_mac_pairs[src_ip]) > 1:
                    logger.warning(f"Multiple MACs for IP {src_ip}")
    
    def _alert_spoofing(self, ip: str, original_mac: str, new_mac: str) -> None:
        message = f"ARP SPOOFING DETECTED! IP: {ip}, Original: {original_mac}, New: {new_mac}"
        logger.critical(message)
        if self.alert_callback:
            self.alert_callback({'ip': ip, 'original_mac': original_mac, 'new_mac': new_mac, 'timestamp': time.time()})
    
    def start_monitoring(self, count: int = 0, timeout: Optional[int] = None) -> None:
        logger.info("Starting ARP spoofing detection...")
        self.is_monitoring = True
        try:
            sniff(iface=self.interface, prn=self._packet_handler, filter="arp", count=count, timeout=timeout, store=False)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped")
        finally:
            self.is_monitoring = False
    
    def get_arp_table(self) -> Dict[str, str]:
        return self.arp_table.copy()
    
    def get_anomalies(self) -> Dict[str, List[str]]:
        return {ip: macs for ip, macs in self.ip_mac_pairs.items() if len(macs) > 1}
