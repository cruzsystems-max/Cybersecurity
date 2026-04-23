"""
Packet Replay Module
⚠️  LABORATORY USE ONLY ⚠️
"""
from scapy.all import sendp, rdpcap
import time
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

class PacketReplay:
    """Replay captured packets"""
    def __init__(self, pcap_file: str):
        self.packets = rdpcap(pcap_file)
        logger.info(f"Loaded {len(self.packets)} packets from {pcap_file}")
    
    def replay(self, count: int = 1, interval: float = 0.1):
        """Replay packets"""
        for i in range(count):
            logger.info(f"Replay iteration {i+1}/{count}")
            for pkt in self.packets:
                sendp(pkt, verbose=0)
                time.sleep(interval)
