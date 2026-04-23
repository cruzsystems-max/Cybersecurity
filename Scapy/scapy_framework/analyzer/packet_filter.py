"""Packet Filter"""
from typing import Callable, Optional
from scapy.all import Packet
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

class PacketFilter:
    """Custom packet filtering"""
    def __init__(self):
        self.filters = []
    
    def add_filter(self, filter_func: Callable[[Packet], bool]):
        """Add filter function"""
        self.filters.append(filter_func)
    
    def apply(self, packet: Packet) -> bool:
        """Apply all filters"""
        return all(f(packet) for f in self.filters)

def filter_by_ip(packet: Packet, ip: str) -> bool:
    """Filter packets by IP"""
    return packet.haslayer('IP') and (packet['IP'].src == ip or packet['IP'].dst == ip)
