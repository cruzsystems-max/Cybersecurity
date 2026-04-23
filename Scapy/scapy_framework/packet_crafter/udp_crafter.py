"""UDP Packet Crafter"""
from scapy.all import IP, UDP
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

class UDPCrafter:
    """UDP packet crafting"""
    def craft(self, dst: str, dport: int, sport: int = 12345, payload: str = ""):
        """Craft UDP packet"""
        packet = IP(dst=dst)/UDP(sport=sport, dport=dport)
        if payload:
            packet = packet/payload
        return packet

def craft_udp_packet(dst: str, dport: int, **kwargs):
    """Quick UDP packet creation"""
    crafter = UDPCrafter()
    return crafter.craft(dst, dport, **kwargs)
