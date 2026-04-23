"""
Packet Sniffer for Scapy Framework

This module provides comprehensive packet capture and analysis capabilities
with filtering, callbacks, statistics, and multiple output formats.
"""

from typing import Optional, Callable, List, Dict, Any, Set
from scapy.all import sniff, wrpcap, rdpcap, Packet, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
import threading
import time
from pathlib import Path
from collections import defaultdict

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.packet_utils import packet_summary, get_packet_layers

logger = get_logger(__name__)


class PacketSniffer:
    """
    Real-time packet sniffer with filtering and analysis.

    Provides comprehensive packet capture with statistics, protocol analysis,
    and flexible callback system.
    """

    def __init__(self,
                 interface: Optional[str] = None,
                 filter: Optional[str] = None,
                 promisc: bool = True,
                 store: bool = True,
                 verbose: bool = False):
        """
        Initialize Packet Sniffer.

        Args:
            interface: Network interface to use (None = default)
            filter: BPF filter string (e.g., "tcp port 80")
            promisc: Enable promiscuous mode
            store: Store captured packets in memory
            verbose: Enable verbose output

        Examples:
            >>> sniffer = PacketSniffer(filter="tcp port 80")
            >>> sniffer = PacketSniffer(interface="eth0", promisc=True)
        """
        self.interface = interface or conf.iface
        self.filter = filter
        self.promisc = promisc
        self.store = store
        self.verbose = verbose

        # Packet storage
        self.packets: List[Packet] = []
        self.packet_count = 0

        # State management
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None

        # Callbacks
        self.callbacks: List[Callable[[Packet], None]] = []

        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'src_ports': defaultdict(int),
            'dst_ports': defaultdict(int),
        }

        if not verbose:
            conf.verb = 0

        logger.info(f"Packet Sniffer initialized on interface {self.interface}")
        if self.filter:
            logger.info(f"BPF filter applied: {self.filter}")

    def add_callback(self, callback: Callable[[Packet], None]) -> None:
        """
        Add a callback function to process each packet.

        Args:
            callback: Function that takes a Packet as argument

        Examples:
            >>> def print_packet(pkt):
            ...     print(pkt.summary())
            >>> sniffer.add_callback(print_packet)
        """
        self.callbacks.append(callback)
        logger.debug(f"Added callback: {callback.__name__}")

    def remove_callback(self, callback: Callable[[Packet], None]) -> None:
        """
        Remove a callback function.

        Args:
            callback: Callback function to remove
        """
        if callback in self.callbacks:
            self.callbacks.remove(callback)
            logger.debug(f"Removed callback: {callback.__name__}")

    def start(self,
              count: int = 0,
              timeout: Optional[int] = None,
              background: bool = False) -> List[Packet]:
        """
        Start packet capture.

        Args:
            count: Number of packets to capture (0 = unlimited)
            timeout: Capture timeout in seconds (None = no timeout)
            background: Run in background thread

        Returns:
            List of captured packets (empty if background=True)

        Examples:
            >>> # Capture 100 packets
            >>> packets = sniffer.start(count=100)
            >>> # Capture for 30 seconds
            >>> packets = sniffer.start(timeout=30)
            >>> # Capture in background
            >>> sniffer.start(background=True)
        """
        if self.is_running:
            logger.warning("Sniffer is already running")
            return []

        logger.info(f"Starting packet capture (count={count}, timeout={timeout})")
        self.is_running = True
        self.start_time = time.time()
        self.packet_count = 0

        if background:
            self.sniffer_thread = threading.Thread(
                target=self._sniff,
                args=(count, timeout),
                daemon=True
            )
            self.sniffer_thread.start()
            logger.info("Packet capture started in background")
            return []
        else:
            return self._sniff(count, timeout)

    def _sniff(self, count: int, timeout: Optional[int]) -> List[Packet]:
        """
        Internal sniffing method.

        Args:
            count: Number of packets to capture
            timeout: Capture timeout

        Returns:
            List of captured packets
        """
        try:
            def packet_handler(pkt: Packet) -> None:
                """Handle each captured packet."""
                self.packet_count += 1

                # Store packet
                if self.store:
                    self.packets.append(pkt)

                # Update statistics
                self._update_stats(pkt)

                # Call registered callbacks
                for callback in self.callbacks:
                    try:
                        callback(pkt)
                    except Exception as e:
                        logger.error(f"Error in callback {callback.__name__}: {e}")

            # Start sniffing
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=packet_handler,
                count=count,
                timeout=timeout,
                store=False,
                promisc=self.promisc
            )

            self.stop_time = time.time()
            self.is_running = False

            duration = self.stop_time - self.start_time if self.start_time else 0
            logger.info(f"Captured {self.packet_count} packets in {duration:.2f}s")

            return self.packets if self.store else []

        except PermissionError:
            logger.error("Permission denied. Packet sniffing requires root/admin privileges.")
            self.is_running = False
            raise PermissionError("Packet sniffing requires elevated privileges")
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")
            self.is_running = False
            raise

    def stop(self) -> None:
        """
        Stop packet capture (when running in background).

        Examples:
            >>> sniffer.start(background=True)
            >>> time.sleep(10)
            >>> sniffer.stop()
        """
        if self.is_running:
            self.is_running = False
            logger.info("Stopping packet capture...")
            if self.sniffer_thread:
                self.sniffer_thread.join(timeout=2)
        else:
            logger.warning("Sniffer is not running")

    def _update_stats(self, packet: Packet) -> None:
        """
        Update packet statistics.

        Args:
            packet: Packet to analyze
        """
        self.stats['total_packets'] += 1

        # Packet size
        if hasattr(packet, '__len__'):
            self.stats['total_bytes'] += len(packet)

        # Protocol statistics
        layers = get_packet_layers(packet)
        for layer in layers:
            self.stats['protocols'][layer] += 1

        # IP statistics
        if packet.haslayer(IP):
            self.stats['src_ips'][packet[IP].src] += 1
            self.stats['dst_ips'][packet[IP].dst] += 1

        # Port statistics
        if packet.haslayer(TCP):
            self.stats['src_ports'][packet[TCP].sport] += 1
            self.stats['dst_ports'][packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            self.stats['src_ports'][packet[UDP].sport] += 1
            self.stats['dst_ports'][packet[UDP].dport] += 1

    def get_packets(self) -> List[Packet]:
        """
        Get all captured packets.

        Returns:
            List of captured packets

        Examples:
            >>> packets = sniffer.get_packets()
            >>> print(f"Captured {len(packets)} packets")
        """
        return self.packets.copy()

    def get_packet_count(self) -> int:
        """
        Get total number of captured packets.

        Returns:
            Packet count
        """
        return len(self.packets)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get capture statistics.

        Returns:
            Dictionary with statistics

        Examples:
            >>> stats = sniffer.get_statistics()
            >>> print(f"Total packets: {stats['total_packets']}")
            >>> print(f"Protocols: {stats['protocols']}")
        """
        duration = 0
        if self.start_time:
            end_time = self.stop_time if self.stop_time else time.time()
            duration = end_time - self.start_time

        return {
            'total_packets': self.stats['total_packets'],
            'total_bytes': self.stats['total_bytes'],
            'duration': duration,
            'packets_per_second': self.stats['total_packets'] / duration if duration > 0 else 0,
            'bytes_per_second': self.stats['total_bytes'] / duration if duration > 0 else 0,
            'protocols': dict(self.stats['protocols']),
            'top_src_ips': self._get_top_n(self.stats['src_ips'], 10),
            'top_dst_ips': self._get_top_n(self.stats['dst_ips'], 10),
            'top_src_ports': self._get_top_n(self.stats['src_ports'], 10),
            'top_dst_ports': self._get_top_n(self.stats['dst_ports'], 10),
        }

    def _get_top_n(self, data: Dict[Any, int], n: int) -> List[tuple]:
        """
        Get top N items from dictionary.

        Args:
            data: Dictionary with counts
            n: Number of top items

        Returns:
            List of (key, count) tuples
        """
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:n]

    def print_statistics(self) -> None:
        """
        Print capture statistics to console.

        Examples:
            >>> sniffer.print_statistics()
        """
        stats = self.get_statistics()

        print("\n" + "=" * 60)
        print("PACKET CAPTURE STATISTICS")
        print("=" * 60)
        print(f"Total Packets:        {stats['total_packets']}")
        print(f"Total Bytes:          {stats['total_bytes']:,}")
        print(f"Duration:             {stats['duration']:.2f} seconds")
        print(f"Packets/sec:          {stats['packets_per_second']:.2f}")
        print(f"Bytes/sec:            {stats['bytes_per_second']:,.2f}")

        print("\nProtocol Distribution:")
        for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_packets']) * 100
            print(f"  {proto:<15} {count:>8} ({percentage:>5.1f}%)")

        if stats['top_src_ips']:
            print("\nTop Source IPs:")
            for ip, count in stats['top_src_ips'][:5]:
                print(f"  {ip:<20} {count:>8}")

        if stats['top_dst_ips']:
            print("\nTop Destination IPs:")
            for ip, count in stats['top_dst_ips'][:5]:
                print(f"  {ip:<20} {count:>8}")

        if stats['top_dst_ports']:
            print("\nTop Destination Ports:")
            for port, count in stats['top_dst_ports'][:5]:
                print(f"  {port:<20} {count:>8}")

        print("=" * 60 + "\n")

    def filter_packets(self, filter_func: Callable[[Packet], bool]) -> List[Packet]:
        """
        Filter captured packets using custom function.

        Args:
            filter_func: Function that returns True for packets to keep

        Returns:
            Filtered list of packets

        Examples:
            >>> # Get only HTTP packets
            >>> http_packets = sniffer.filter_packets(lambda p: p.haslayer(TCP) and p[TCP].dport == 80)
            >>> # Get packets from specific IP
            >>> ip_packets = sniffer.filter_packets(lambda p: p.haslayer(IP) and p[IP].src == '192.168.1.1')
        """
        return [pkt for pkt in self.packets if filter_func(pkt)]

    def get_packets_by_protocol(self, protocol: str) -> List[Packet]:
        """
        Get packets of a specific protocol.

        Args:
            protocol: Protocol name (TCP, UDP, ICMP, ARP, DNS, etc.)

        Returns:
            List of packets with that protocol

        Examples:
            >>> tcp_packets = sniffer.get_packets_by_protocol('TCP')
            >>> dns_packets = sniffer.get_packets_by_protocol('DNS')
        """
        return [pkt for pkt in self.packets if pkt.haslayer(protocol)]

    def get_packets_by_ip(self, ip: str, src: bool = True, dst: bool = True) -> List[Packet]:
        """
        Get packets involving a specific IP address.

        Args:
            ip: IP address to filter
            src: Include packets with this IP as source
            dst: Include packets with this IP as destination

        Returns:
            List of filtered packets

        Examples:
            >>> packets = sniffer.get_packets_by_ip('192.168.1.1')
            >>> src_packets = sniffer.get_packets_by_ip('192.168.1.1', dst=False)
        """
        result = []
        for pkt in self.packets:
            if pkt.haslayer(IP):
                if src and pkt[IP].src == ip:
                    result.append(pkt)
                elif dst and pkt[IP].dst == ip:
                    result.append(pkt)
        return result

    def get_packets_by_port(self, port: int, src: bool = True, dst: bool = True) -> List[Packet]:
        """
        Get packets involving a specific port.

        Args:
            port: Port number to filter
            src: Include packets with this port as source
            dst: Include packets with this port as destination

        Returns:
            List of filtered packets

        Examples:
            >>> http_packets = sniffer.get_packets_by_port(80)
            >>> https_packets = sniffer.get_packets_by_port(443, src=False)
        """
        result = []
        for pkt in self.packets:
            if pkt.haslayer(TCP):
                if src and pkt[TCP].sport == port:
                    result.append(pkt)
                elif dst and pkt[TCP].dport == port:
                    result.append(pkt)
            elif pkt.haslayer(UDP):
                if src and pkt[UDP].sport == port:
                    result.append(pkt)
                elif dst and pkt[UDP].dport == port:
                    result.append(pkt)
        return result

    def save_pcap(self, filename: str, packets: Optional[List[Packet]] = None) -> None:
        """
        Save packets to PCAP file.

        Args:
            filename: Output filename
            packets: Packets to save (None = all captured packets)

        Examples:
            >>> sniffer.save_pcap('capture.pcap')
            >>> # Save only HTTP packets
            >>> http = sniffer.get_packets_by_port(80)
            >>> sniffer.save_pcap('http.pcap', http)
        """
        packets_to_save = packets if packets is not None else self.packets

        if not packets_to_save:
            logger.warning("No packets to save")
            return

        try:
            wrpcap(filename, packets_to_save)
            logger.info(f"Saved {len(packets_to_save)} packets to {filename}")
        except Exception as e:
            logger.error(f"Failed to save PCAP: {e}")
            raise

    def load_pcap(self, filename: str) -> List[Packet]:
        """
        Load packets from PCAP file.

        Args:
            filename: PCAP file to load

        Returns:
            List of loaded packets

        Examples:
            >>> packets = sniffer.load_pcap('capture.pcap')
        """
        try:
            packets = rdpcap(filename)
            self.packets.extend(packets)
            logger.info(f"Loaded {len(packets)} packets from {filename}")

            # Update statistics
            for pkt in packets:
                self._update_stats(pkt)

            return packets

        except Exception as e:
            logger.error(f"Failed to load PCAP: {e}")
            raise

    def export_summary(self, filename: str, format: str = 'txt') -> None:
        """
        Export packet summaries to file.

        Args:
            filename: Output filename
            format: Export format ('txt', 'csv', 'json')

        Examples:
            >>> sniffer.export_summary('summary.txt')
            >>> sniffer.export_summary('summary.csv', format='csv')
        """
        import json
        import csv

        if not self.packets:
            logger.warning("No packets to export")
            return

        if format == 'txt':
            with open(filename, 'w') as f:
                f.write("PACKET CAPTURE SUMMARY\n")
                f.write("=" * 80 + "\n\n")
                for i, pkt in enumerate(self.packets, 1):
                    f.write(f"[{i}] {pkt.summary()}\n")

        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['#', 'Time', 'Source', 'Destination', 'Protocol', 'Info'])

                for i, pkt in enumerate(self.packets, 1):
                    src = pkt[IP].src if pkt.haslayer(IP) else 'N/A'
                    dst = pkt[IP].dst if pkt.haslayer(IP) else 'N/A'
                    proto = pkt.lastlayer().name
                    info = pkt.summary()

                    writer.writerow([i, pkt.time if hasattr(pkt, 'time') else '', src, dst, proto, info])

        elif format == 'json':
            summaries = []
            for i, pkt in enumerate(self.packets, 1):
                summaries.append({
                    'packet_num': i,
                    'summary': pkt.summary(),
                    'layers': get_packet_layers(pkt)
                })

            with open(filename, 'w') as f:
                json.dump(summaries, f, indent=2)

        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported summary to {filename}")

    def clear(self) -> None:
        """
        Clear captured packets and reset statistics.

        Examples:
            >>> sniffer.clear()
        """
        self.packets.clear()
        self.packet_count = 0
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'src_ports': defaultdict(int),
            'dst_ports': defaultdict(int),
        }
        logger.info("Cleared packets and statistics")


def sniff_packets(interface: Optional[str] = None,
                  filter: Optional[str] = None,
                  count: int = 100,
                  timeout: Optional[int] = None) -> List[Packet]:
    """
    Quick packet sniffing function.

    Args:
        interface: Network interface to use
        filter: BPF filter string
        count: Number of packets to capture
        timeout: Capture timeout in seconds

    Returns:
        List of captured packets

    Examples:
        >>> packets = sniff_packets(count=50)
        >>> http_packets = sniff_packets(filter="tcp port 80", count=100)
    """
    sniffer = PacketSniffer(interface=interface, filter=filter)
    return sniffer.start(count=count, timeout=timeout)
