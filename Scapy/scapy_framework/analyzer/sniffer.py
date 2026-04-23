"""
Packet Sniffer for Scapy Framework

This module provides real-time packet capture and analysis capabilities
with filtering, callbacks, and multiple output formats.
"""

from typing import Optional, Callable, List, Dict, Any
from scapy.all import sniff, wrpcap, Packet, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
import threading
import time
from pathlib import Path

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.packet_utils import packet_summary, get_packet_layers


logger = get_logger(__name__)


class PacketSniffer:
    """Real-time packet sniffer with filtering and analysis."""

    def __init__(self,
                 interface: Optional[str] = None,
                 filter: Optional[str] = None,
                 promisc: bool = True,
                 store: bool = True):
        """Initialize Packet Sniffer."""
        self.interface = interface or conf.iface
        self.filter = filter
        self.promisc = promisc
        self.store = store
        self.packets: List[Packet] = []
        self.packet_count = 0
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.callbacks: List[Callable[[Packet], None]] = []
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None

        logger.info(f"Packet Sniffer initialized on interface {self.interface}")
        if self.filter:
            logger.info(f"BPF filter applied: {self.filter}")

    def start(self, count: int = 0, timeout: Optional[int] = None, background: bool = False) -> List[Packet]:
        """Start packet capture."""
        if self.is_running:
            logger.warning("Sniffer is already running")
            return []

        logger.info(f"Starting packet capture (count={count}, timeout={timeout})")
        self.is_running = True
        self.start_time = time.time()
        self.packet_count = 0

        if background:
            self.sniffer_thread = threading.Thread(
                target=self._sniff, args=(count, timeout), daemon=True
            )
            self.sniffer_thread.start()
            logger.info("Packet capture started in background")
            return []
        else:
            return self._sniff(count, timeout)

    def _sniff(self, count: int, timeout: Optional[int]) -> List[Packet]:
        """Internal sniffing method."""
        try:
            def packet_handler(pkt):
                self.packet_count += 1
                if self.store:
                    self.packets.append(pkt)
                for callback in self.callbacks:
                    try:
                        callback(pkt)
                    except Exception as e:
                        logger.error(f"Error in callback: {e}")

            packets = sniff(
                iface=self.interface, filter=self.filter, prn=packet_handler,
                count=count, timeout=timeout, store=False, promisc=self.promisc
            )

            self.stop_time = time.time()
            self.is_running = False
            duration = self.stop_time - self.start_time if self.start_time else 0
            logger.info(f"Captured {self.packet_count} packets in {duration:.2f}s")
            return self.packets if self.store else []

        except PermissionError:
            logger.error("Permission denied. Requires elevated privileges.")
            self.is_running = False
            raise PermissionError("Packet sniffing requires elevated privileges")
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")
            self.is_running = False
            raise

    def get_packets(self) -> List[Packet]:
        """Get captured packets."""
        return self.packets

    def save_packets(self, filename: str) -> None:
        """Save captured packets to PCAP file."""
        if not self.packets:
            logger.warning("No packets to save")
            return
        try:
            wrpcap(filename, self.packets)
            logger.info(f"Saved {len(self.packets)} packets to {filename}")
        except Exception as e:
            logger.error(f"Failed to save packets: {e}")
            raise


def sniff_packets(interface: Optional[str] = None, filter: Optional[str] = None,
                 count: int = 100, timeout: Optional[int] = None) -> List[Packet]:
    """Quick packet sniffing function."""
    sniffer = PacketSniffer(interface=interface, filter=filter)
    return sniffer.start(count=count, timeout=timeout)
