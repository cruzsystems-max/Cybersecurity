\"\"\"
TCP Packet Crafting Module
\"\"\"

from typing import Optional
from scapy.all import IP, TCP, send, sr1, conf
import random
from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_ip, is_valid_port

logger = get_logger(__name__)

class TCPCrafter:
    \"\"\"Crafts and sends custom TCP packets.\"\"\"
    
    def __init__(self, interface: Optional[str] = None, verbose: bool = False):
        self.interface = interface or conf.iface
        self.verbose = verbose
        logger.info(f"TCP Crafter initialized")
    
    def craft_syn(self, dst_ip: str, dst_port: int, src_port: Optional[int] = None):
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid IP: {dst_ip}")
        if not is_valid_port(dst_port):
            raise ValueError(f"Invalid port: {dst_port}")
        
        if src_port is None:
            src_port = random.randint(1024, 65535)
        
        packet = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S', seq=random.randint(1000, 100000))
        logger.debug(f"Crafted SYN packet: {dst_ip}:{dst_port}")
        return packet
    
    def craft_ack(self, dst_ip: str, dst_port: int, src_port: int, seq: int, ack: int):
        packet = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=seq, ack=ack)
        return packet
    
    def send_packet(self, packet, count: int = 1) -> None:
        logger.info(f"Sending {count} packet(s)...")
        send(packet, iface=self.interface, count=count, verbose=self.verbose)
    
    def send_and_receive(self, packet, timeout: int = 2):
        logger.info("Sending packet and waiting for response...")
        response = sr1(packet, iface=self.interface, timeout=timeout, verbose=self.verbose)
        if response:
            logger.info(f"Received: {response.summary()}")
        return response
