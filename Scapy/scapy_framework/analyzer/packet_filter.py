"""
Packet Filtering Module for Scapy Framework

This module provides advanced packet filtering capabilities with predefined filters,
custom filter functions, and filter composition.
"""

from typing import Callable, Optional, List, Union, Set
from scapy.all import Packet, IP, TCP, UDP, ICMP, ARP, DNS
import re

from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)


class PacketFilter:
    """
    Advanced packet filter with support for multiple filter types and composition.

    Supports combining filters with AND, OR, NOT operations and provides
    predefined filters for common use cases.
    """

    def __init__(self):
        """
        Initialize Packet Filter.

        Examples:
            >>> filter = PacketFilter()
            >>> filter.add_filter(lambda p: p.haslayer(TCP))
        """
        self.filters: List[Callable[[Packet], bool]] = []
        logger.debug("PacketFilter initialized")

    def add_filter(self, filter_func: Callable[[Packet], bool]) -> 'PacketFilter':
        """
        Add a filter function.

        Args:
            filter_func: Function that takes a Packet and returns bool

        Returns:
            Self for method chaining

        Examples:
            >>> filter = PacketFilter()
            >>> filter.add_filter(lambda p: p.haslayer(TCP))
            >>> filter.add_filter(lambda p: p[TCP].dport == 80)
        """
        self.filters.append(filter_func)
        logger.debug(f"Added filter function: {filter_func.__name__ if hasattr(filter_func, '__name__') else 'lambda'}")
        return self

    def remove_filter(self, filter_func: Callable[[Packet], bool]) -> 'PacketFilter':
        """
        Remove a filter function.

        Args:
            filter_func: Filter function to remove

        Returns:
            Self for method chaining
        """
        if filter_func in self.filters:
            self.filters.remove(filter_func)
            logger.debug("Removed filter function")
        return self

    def clear_filters(self) -> 'PacketFilter':
        """
        Clear all filters.

        Returns:
            Self for method chaining
        """
        self.filters.clear()
        logger.debug("Cleared all filters")
        return self

    def apply(self, packet: Packet) -> bool:
        """
        Apply all filters to a packet (AND logic).

        Args:
            packet: Packet to filter

        Returns:
            True if packet passes all filters

        Examples:
            >>> filter = PacketFilter()
            >>> filter.add_filter(lambda p: p.haslayer(IP))
            >>> if filter.apply(packet):
            ...     print("Packet passed filter")
        """
        if not self.filters:
            return True

        return all(f(packet) for f in self.filters)

    def apply_or(self, packet: Packet) -> bool:
        """
        Apply filters with OR logic.

        Args:
            packet: Packet to filter

        Returns:
            True if packet passes any filter

        Examples:
            >>> filter = PacketFilter()
            >>> filter.add_filter(lambda p: p.haslayer(TCP))
            >>> filter.add_filter(lambda p: p.haslayer(UDP))
            >>> if filter.apply_or(packet):
            ...     print("Packet is TCP or UDP")
        """
        if not self.filters:
            return True

        return any(f(packet) for f in self.filters)

    def filter_packets(self, packets: List[Packet], use_or: bool = False) -> List[Packet]:
        """
        Filter a list of packets.

        Args:
            packets: List of packets to filter
            use_or: Use OR logic instead of AND

        Returns:
            Filtered list of packets

        Examples:
            >>> filtered = filter.filter_packets(packets)
        """
        apply_func = self.apply_or if use_or else self.apply
        result = [pkt for pkt in packets if apply_func(pkt)]
        logger.info(f"Filtered {len(packets)} packets -> {len(result)} packets")
        return result

    def get_filter_count(self) -> int:
        """
        Get number of active filters.

        Returns:
            Number of filters
        """
        return len(self.filters)


# Predefined filter functions

def filter_by_protocol(packet: Packet, protocol: str) -> bool:
    """
    Filter packets by protocol layer.

    Args:
        packet: Packet to check
        protocol: Protocol name (IP, TCP, UDP, ICMP, ARP, DNS, etc.)

    Returns:
        True if packet has the protocol layer

    Examples:
        >>> tcp_filter = lambda p: filter_by_protocol(p, 'TCP')
    """
    return packet.haslayer(protocol)


def filter_by_ip(packet: Packet, ip: str, src: bool = True, dst: bool = True) -> bool:
    """
    Filter packets by IP address.

    Args:
        packet: Packet to check
        ip: IP address to match
        src: Check source IP
        dst: Check destination IP

    Returns:
        True if packet matches IP criteria

    Examples:
        >>> src_filter = lambda p: filter_by_ip(p, '192.168.1.1', dst=False)
    """
    if not packet.haslayer(IP):
        return False

    if src and packet[IP].src == ip:
        return True
    if dst and packet[IP].dst == ip:
        return True

    return False


def filter_by_ip_range(packet: Packet, ip_range: str, src: bool = True, dst: bool = True) -> bool:
    """
    Filter packets by IP range (CIDR notation).

    Args:
        packet: Packet to check
        ip_range: IP range in CIDR notation (e.g., '192.168.1.0/24')
        src: Check source IP
        dst: Check destination IP

    Returns:
        True if packet IP is in range
    """
    from ipaddress import ip_address, ip_network

    if not packet.haslayer(IP):
        return False

    network = ip_network(ip_range, strict=False)

    if src and ip_address(packet[IP].src) in network:
        return True
    if dst and ip_address(packet[IP].dst) in network:
        return True

    return False


def filter_by_port(packet: Packet, port: int, src: bool = True, dst: bool = True) -> bool:
    """
    Filter packets by port number.

    Args:
        packet: Packet to check
        port: Port number to match
        src: Check source port
        dst: Check destination port

    Returns:
        True if packet matches port criteria

    Examples:
        >>> http_filter = lambda p: filter_by_port(p, 80, src=False)
    """
    if packet.haslayer(TCP):
        if src and packet[TCP].sport == port:
            return True
        if dst and packet[TCP].dport == port:
            return True
    elif packet.haslayer(UDP):
        if src and packet[UDP].sport == port:
            return True
        if dst and packet[UDP].dport == port:
            return True

    return False


def filter_by_port_range(packet: Packet, start_port: int, end_port: int,
                         src: bool = True, dst: bool = True) -> bool:
    """
    Filter packets by port range.

    Args:
        packet: Packet to check
        start_port: Starting port (inclusive)
        end_port: Ending port (inclusive)
        src: Check source port
        dst: Check destination port

    Returns:
        True if packet port is in range

    Examples:
        >>> high_ports = lambda p: filter_by_port_range(p, 1024, 65535, dst=False)
    """
    if packet.haslayer(TCP):
        if src and start_port <= packet[TCP].sport <= end_port:
            return True
        if dst and start_port <= packet[TCP].dport <= end_port:
            return True
    elif packet.haslayer(UDP):
        if src and start_port <= packet[UDP].sport <= end_port:
            return True
        if dst and start_port <= packet[UDP].dport <= end_port:
            return True

    return False


def filter_by_tcp_flags(packet: Packet, flags: str) -> bool:
    """
    Filter TCP packets by flags.

    Args:
        packet: Packet to check
        flags: TCP flags (S=SYN, A=ACK, F=FIN, R=RST, P=PSH, U=URG)

    Returns:
        True if TCP packet has specified flags

    Examples:
        >>> syn_filter = lambda p: filter_by_tcp_flags(p, 'S')
        >>> syn_ack_filter = lambda p: filter_by_tcp_flags(p, 'SA')
    """
    if not packet.haslayer(TCP):
        return False

    return packet[TCP].flags == flags


def filter_by_packet_size(packet: Packet, min_size: int = 0, max_size: int = 65535) -> bool:
    """
    Filter packets by size.

    Args:
        packet: Packet to check
        min_size: Minimum packet size in bytes
        max_size: Maximum packet size in bytes

    Returns:
        True if packet size is in range

    Examples:
        >>> large_packets = lambda p: filter_by_packet_size(p, min_size=1000)
    """
    if hasattr(packet, '__len__'):
        size = len(packet)
        return min_size <= size <= max_size
    return False


def filter_by_dns_query(packet: Packet, domain: Optional[str] = None) -> bool:
    """
    Filter DNS query packets.

    Args:
        packet: Packet to check
        domain: Optional domain name to match (supports wildcards)

    Returns:
        True if packet is DNS query (optionally matching domain)

    Examples:
        >>> dns_filter = lambda p: filter_by_dns_query(p)
        >>> google_dns = lambda p: filter_by_dns_query(p, '*.google.com')
    """
    if not packet.haslayer(DNS):
        return False

    # Check if it's a query (qr=0)
    if packet[DNS].qr != 0:
        return False

    if domain:
        if packet[DNS].qd:
            qname = packet[DNS].qd.qname.decode() if isinstance(packet[DNS].qd.qname, bytes) else str(packet[DNS].qd.qname)
            # Convert wildcard to regex
            pattern = domain.replace('.', '\\.').replace('*', '.*')
            return bool(re.match(pattern, qname, re.IGNORECASE))

    return True


def filter_by_icmp_type(packet: Packet, icmp_type: int) -> bool:
    """
    Filter ICMP packets by type.

    Args:
        packet: Packet to check
        icmp_type: ICMP type (e.g., 8=Echo Request, 0=Echo Reply)

    Returns:
        True if ICMP packet matches type

    Examples:
        >>> ping_filter = lambda p: filter_by_icmp_type(p, 8)
    """
    if not packet.haslayer(ICMP):
        return False

    return packet[ICMP].type == icmp_type


def filter_arp_packets(packet: Packet, op: Optional[int] = None) -> bool:
    """
    Filter ARP packets.

    Args:
        packet: Packet to check
        op: Optional ARP operation (1=request, 2=reply)

    Returns:
        True if packet is ARP (optionally matching operation)

    Examples:
        >>> arp_request = lambda p: filter_arp_packets(p, op=1)
    """
    if not packet.haslayer(ARP):
        return False

    if op is not None:
        return packet[ARP].op == op

    return True


def filter_broadcast(packet: Packet) -> bool:
    """
    Filter broadcast packets.

    Args:
        packet: Packet to check

    Returns:
        True if packet is broadcast
    """
    if packet.haslayer('Ether'):
        return packet['Ether'].dst == 'ff:ff:ff:ff:ff:ff'
    return False


def filter_multicast(packet: Packet) -> bool:
    """
    Filter multicast packets.

    Args:
        packet: Packet to check

    Returns:
        True if packet is multicast
    """
    if packet.haslayer(IP):
        # Multicast IP range: 224.0.0.0/4
        first_octet = int(packet[IP].dst.split('.')[0])
        return 224 <= first_octet <= 239
    return False


# Filter builders

class FilterBuilder:
    """
    Fluent interface for building complex filters.

    Examples:
        >>> filter = FilterBuilder() \\
        ...     .protocol('TCP') \\
        ...     .port(80) \\
        ...     .ip('192.168.1.1') \\
        ...     .build()
    """

    def __init__(self):
        """Initialize filter builder."""
        self.packet_filter = PacketFilter()

    def protocol(self, protocol: str) -> 'FilterBuilder':
        """
        Add protocol filter.

        Args:
            protocol: Protocol name (TCP, UDP, ICMP, etc.)

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_protocol(p, protocol))
        return self

    def ip(self, ip: str, src: bool = True, dst: bool = True) -> 'FilterBuilder':
        """
        Add IP filter.

        Args:
            ip: IP address
            src: Filter source IP
            dst: Filter destination IP

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_ip(p, ip, src, dst))
        return self

    def ip_range(self, ip_range: str, src: bool = True, dst: bool = True) -> 'FilterBuilder':
        """
        Add IP range filter.

        Args:
            ip_range: IP range in CIDR notation
            src: Filter source IP
            dst: Filter destination IP

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_ip_range(p, ip_range, src, dst))
        return self

    def port(self, port: int, src: bool = True, dst: bool = True) -> 'FilterBuilder':
        """
        Add port filter.

        Args:
            port: Port number
            src: Filter source port
            dst: Filter destination port

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_port(p, port, src, dst))
        return self

    def port_range(self, start: int, end: int, src: bool = True, dst: bool = True) -> 'FilterBuilder':
        """
        Add port range filter.

        Args:
            start: Start port
            end: End port
            src: Filter source port
            dst: Filter destination port

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_port_range(p, start, end, src, dst))
        return self

    def tcp_flags(self, flags: str) -> 'FilterBuilder':
        """
        Add TCP flags filter.

        Args:
            flags: TCP flags string

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_tcp_flags(p, flags))
        return self

    def size(self, min_size: int = 0, max_size: int = 65535) -> 'FilterBuilder':
        """
        Add packet size filter.

        Args:
            min_size: Minimum size
            max_size: Maximum size

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_packet_size(p, min_size, max_size))
        return self

    def dns(self, domain: Optional[str] = None) -> 'FilterBuilder':
        """
        Add DNS filter.

        Args:
            domain: Optional domain name

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(lambda p: filter_by_dns_query(p, domain))
        return self

    def custom(self, filter_func: Callable[[Packet], bool]) -> 'FilterBuilder':
        """
        Add custom filter function.

        Args:
            filter_func: Custom filter function

        Returns:
            Self for chaining
        """
        self.packet_filter.add_filter(filter_func)
        return self

    def build(self) -> PacketFilter:
        """
        Build and return the packet filter.

        Returns:
            Configured PacketFilter instance
        """
        return self.packet_filter


# Common pre-configured filters

def get_http_filter() -> PacketFilter:
    """
    Get filter for HTTP traffic (ports 80, 8080).

    Returns:
        Configured PacketFilter
    """
    return FilterBuilder().protocol('TCP').port(80).build()


def get_https_filter() -> PacketFilter:
    """
    Get filter for HTTPS traffic (port 443).

    Returns:
        Configured PacketFilter
    """
    return FilterBuilder().protocol('TCP').port(443).build()


def get_dns_filter() -> PacketFilter:
    """
    Get filter for DNS traffic.

    Returns:
        Configured PacketFilter
    """
    return FilterBuilder().protocol('UDP').port(53).build()


def get_ssh_filter() -> PacketFilter:
    """
    Get filter for SSH traffic (port 22).

    Returns:
        Configured PacketFilter
    """
    return FilterBuilder().protocol('TCP').port(22).build()


def get_ping_filter() -> PacketFilter:
    """
    Get filter for ICMP ping packets.

    Returns:
        Configured PacketFilter
    """
    filter = PacketFilter()
    filter.add_filter(lambda p: filter_by_icmp_type(p, 8))
    return filter
