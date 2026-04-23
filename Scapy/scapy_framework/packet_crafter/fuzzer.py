"""Packet Fuzzer"""
from scapy.all import fuzz
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

class PacketFuzzer:
    """Basic packet fuzzer"""
    def fuzz(self, packet, count: int = 10):
        """Fuzz packet fields"""
        return [fuzz(packet) for _ in range(count)]

def fuzz_packet(packet, count: int = 10):
    """Quick packet fuzzing"""
    fuzzer = PacketFuzzer()
    return fuzzer.fuzz(packet, count)
