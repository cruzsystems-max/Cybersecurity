"""ICMP Packet Crafter"""
from scapy.all import IP, ICMP
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

class ICMPCrafter:
    """ICMP packet crafting"""
    def craft_ping(self, dst: str, id: int = 1, seq: int = 1):
        """Craft ICMP echo request"""
        return IP(dst=dst)/ICMP(id=id, seq=seq)

def craft_icmp_packet(dst: str, **kwargs):
    """Quick ICMP packet creation"""
    crafter = ICMPCrafter()
    return crafter.craft_ping(dst, **kwargs)
