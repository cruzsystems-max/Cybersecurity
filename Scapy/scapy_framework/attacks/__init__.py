"""
Attacks module for Scapy Framework

⚠️  CRITICAL ETHICAL WARNING ⚠️

This module contains tools for network security testing and educational purposes ONLY.
All tools require explicit authorization before use.

UNAUTHORIZED USE IS ILLEGAL AND UNETHICAL.

Use only in:
- Controlled laboratory environments
- Authorized penetration testing with written permission
- Educational demonstrations with proper authorization
- Your own network infrastructure

The authors and contributors assume NO responsibility for misuse.
"""

from .arp_spoofing import ARPSpoofer, arp_spoof
from .dns_spoofing import DNSSpoofer, dns_spoof
from .packet_replay import PacketReplayer, replay_pcap

__all__ = [
    # ARP Spoofing
    'ARPSpoofer',
    'arp_spoof',
    # DNS Spoofing
    'DNSSpoofer',
    'dns_spoof',
    # Packet Replay
    'PacketReplayer',
    'replay_pcap',
]

# Display ethical warning on import
import warnings
warnings.warn(
    "\n"
    "⚠️  ETHICAL WARNING ⚠️\n"
    "You have imported the attacks module.\n"
    "These tools are for AUTHORIZED SECURITY TESTING ONLY.\n"
    "Unauthorized use is ILLEGAL.\n",
    UserWarning,
    stacklevel=2
)
