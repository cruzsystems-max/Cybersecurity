"""
Packet Utilities for Scapy Framework

This module provides utility functions for packet manipulation and analysis.
"""

from typing import Optional, Dict, Any, List
from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, Raw
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP


def packet_summary(packet: Packet, detailed: bool = False) -> str:
    """
    Get a human-readable summary of a packet.

    Args:
        packet: Scapy packet object
        detailed: If True, includes more details

    Returns:
        Packet summary string

    Examples:
        >>> from scapy.all import IP, TCP
        >>> pkt = IP(dst='8.8.8.8')/TCP(dport=80)
        >>> print(packet_summary(pkt))
        'IP / TCP 127.0.0.1:ftp_data > 8.8.8.8:http S'
    """
    if detailed:
        return packet.show(dump=True)
    else:
        return packet.summary()


def extract_layer(packet: Packet, layer) -> Optional[Any]:
    """
    Extract a specific layer from a packet.

    Args:
        packet: Scapy packet object
        layer: Layer class to extract (e.g., IP, TCP, etc.)

    Returns:
        Layer object if found, None otherwise

    Examples:
        >>> ip_layer = extract_layer(packet, IP)
        >>> if ip_layer:
        ...     print(ip_layer.src, ip_layer.dst)
    """
    if packet.haslayer(layer):
        return packet.getlayer(layer)
    return None


def has_layer(packet: Packet, layer) -> bool:
    """
    Check if a packet contains a specific layer.

    Args:
        packet: Scapy packet object
        layer: Layer class to check

    Returns:
        True if packet has the layer, False otherwise

    Examples:
        >>> if has_layer(packet, TCP):
        ...     print('Packet contains TCP layer')
    """
    return packet.haslayer(layer)


def get_packet_size(packet: Packet) -> int:
    """
    Get the total size of a packet in bytes.

    Args:
        packet: Scapy packet object

    Returns:
        Packet size in bytes

    Examples:
        >>> size = get_packet_size(packet)
        >>> print(f"Packet size: {size} bytes")
    """
    return len(packet)


def packet_to_dict(packet: Packet) -> Dict[str, Any]:
    """
    Convert a packet to a dictionary representation.

    Args:
        packet: Scapy packet object

    Returns:
        Dictionary with packet information

    Examples:
        >>> pkt_dict = packet_to_dict(packet)
        >>> print(pkt_dict['src_ip'])
    """
    result = {
        'timestamp': packet.time if hasattr(packet, 'time') else None,
        'size': len(packet),
        'layers': []
    }

    # Extract common layers
    if packet.haslayer(Ether):
        ether = packet[Ether]
        result['src_mac'] = ether.src
        result['dst_mac'] = ether.dst
        result['layers'].append('Ethernet')

    if packet.haslayer(ARP):
        arp = packet[ARP]
        result['protocol'] = 'ARP'
        result['src_ip'] = arp.psrc
        result['dst_ip'] = arp.pdst
        result['arp_op'] = arp.op
        result['layers'].append('ARP')

    if packet.haslayer(IP):
        ip = packet[IP]
        result['src_ip'] = ip.src
        result['dst_ip'] = ip.dst
        result['ttl'] = ip.ttl
        result['protocol'] = ip.proto
        result['layers'].append('IP')

    if packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        result['src_ip'] = ipv6.src
        result['dst_ip'] = ipv6.dst
        result['protocol'] = ipv6.nh
        result['layers'].append('IPv6')

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result['src_port'] = tcp.sport
        result['dst_port'] = tcp.dport
        result['tcp_flags'] = tcp.flags
        result['seq'] = tcp.seq
        result['ack'] = tcp.ack
        result['transport'] = 'TCP'
        result['layers'].append('TCP')

    if packet.haslayer(UDP):
        udp = packet[UDP]
        result['src_port'] = udp.sport
        result['dst_port'] = udp.dport
        result['transport'] = 'UDP'
        result['layers'].append('UDP')

    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        result['icmp_type'] = icmp.type
        result['icmp_code'] = icmp.code
        result['transport'] = 'ICMP'
        result['layers'].append('ICMP')

    if packet.haslayer(DNS):
        result['layers'].append('DNS')
        result['application'] = 'DNS'

    if packet.haslayer(Raw):
        raw = packet[Raw]
        result['payload'] = bytes(raw.load)
        result['payload_size'] = len(raw.load)
        result['layers'].append('Raw')

    return result


def analyze_packet(packet: Packet) -> Dict[str, Any]:
    """
    Perform detailed analysis of a packet.

    Args:
        packet: Scapy packet object

    Returns:
        Dictionary with packet analysis

    Examples:
        >>> analysis = analyze_packet(packet)
        >>> print(f"Protocol: {analysis['protocol']}")
    """
    analysis = packet_to_dict(packet)

    # Add additional analysis
    if 'src_ip' in analysis and 'dst_ip' in analysis:
        analysis['direction'] = 'outbound' if analysis['src_ip'].startswith(('192.168.', '10.', '172.')) else 'inbound'

    if 'tcp_flags' in analysis:
        flags = str(analysis['tcp_flags'])
        analysis['tcp_flags_verbose'] = {
            'SYN': 'S' in flags,
            'ACK': 'A' in flags,
            'FIN': 'F' in flags,
            'RST': 'R' in flags,
            'PSH': 'P' in flags,
            'URG': 'U' in flags
        }

    return analysis


def get_layer_names(packet: Packet) -> List[str]:
    """
    Get list of all layer names in a packet.

    Args:
        packet: Scapy packet object

    Returns:
        List of layer names

    Examples:
        >>> layers = get_layer_names(packet)
        >>> print(layers)
        ['Ethernet', 'IP', 'TCP', 'Raw']
    """
    layers = []
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        layers.append(layer.name)
        counter += 1
    return layers


def extract_payload(packet: Packet) -> Optional[bytes]:
    """
    Extract payload data from a packet.

    Args:
        packet: Scapy packet object

    Returns:
        Payload bytes if present, None otherwise

    Examples:
        >>> payload = extract_payload(packet)
        >>> if payload:
        ...     print(payload.decode('utf-8', errors='ignore'))
    """
    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)
    return None


def is_tcp_handshake(packet: Packet) -> bool:
    """
    Check if packet is part of TCP 3-way handshake.

    Args:
        packet: Scapy packet object

    Returns:
        True if packet is SYN, SYN-ACK, or final ACK

    Examples:
        >>> if is_tcp_handshake(packet):
        ...     print('TCP handshake packet detected')
    """
    if not packet.haslayer(TCP):
        return False

    tcp = packet[TCP]
    flags = str(tcp.flags)

    # SYN only (first step)
    if flags == 'S':
        return True

    # SYN-ACK (second step)
    if 'S' in flags and 'A' in flags:
        return True

    # ACK only with no payload (third step)
    if flags == 'A' and not packet.haslayer(Raw):
        return True

    return False


def get_protocol_name(packet: Packet) -> str:
    """
    Get the highest-level protocol name from a packet.

    Args:
        packet: Scapy packet object

    Returns:
        Protocol name as string

    Examples:
        >>> proto = get_protocol_name(packet)
        >>> print(f"Protocol: {proto}")
    """
    if packet.haslayer(DNS):
        return 'DNS'
    elif packet.haslayer(TCP):
        return 'TCP'
    elif packet.haslayer(UDP):
        return 'UDP'
    elif packet.haslayer(ICMP):
        return 'ICMP'
    elif packet.haslayer(ARP):
        return 'ARP'
    elif packet.haslayer(IP):
        return 'IP'
    elif packet.haslayer(IPv6):
        return 'IPv6'
    elif packet.haslayer(Ether):
        return 'Ethernet'
    else:
        return 'Unknown'


def packets_to_pcap(packets: List[Packet], filename: str) -> None:
    """
    Save a list of packets to a PCAP file.

    Args:
        packets: List of Scapy packet objects
        filename: Output filename

    Examples:
        >>> packets_to_pcap(captured_packets, 'capture.pcap')
    """
    from scapy.all import wrpcap
    wrpcap(filename, packets)


def pcap_to_packets(filename: str) -> List[Packet]:
    """
    Load packets from a PCAP file.

    Args:
        filename: PCAP file path

    Returns:
        List of Scapy packet objects

    Examples:
        >>> packets = pcap_to_packets('capture.pcap')
        >>> print(f"Loaded {len(packets)} packets")
    """
    from scapy.all import rdpcap
    return rdpcap(filename)
