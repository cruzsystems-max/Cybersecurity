"""
Analyzer module for Scapy Framework

This module provides packet capture, analysis, and filtering capabilities.
"""

from .sniffer import PacketSniffer, sniff_packets
from .packet_filter import (
    PacketFilter,
    FilterBuilder,
    filter_by_protocol,
    filter_by_ip,
    filter_by_ip_range,
    filter_by_port,
    filter_by_port_range,
    filter_by_tcp_flags,
    filter_by_packet_size,
    filter_by_dns_query,
    filter_by_icmp_type,
    filter_arp_packets,
    filter_broadcast,
    filter_multicast,
    get_http_filter,
    get_https_filter,
    get_dns_filter,
    get_ssh_filter,
    get_ping_filter,
)

__all__ = [
    # Sniffer
    'PacketSniffer',
    'sniff_packets',
    # Filters
    'PacketFilter',
    'FilterBuilder',
    'filter_by_protocol',
    'filter_by_ip',
    'filter_by_ip_range',
    'filter_by_port',
    'filter_by_port_range',
    'filter_by_tcp_flags',
    'filter_by_packet_size',
    'filter_by_dns_query',
    'filter_by_icmp_type',
    'filter_arp_packets',
    'filter_broadcast',
    'filter_multicast',
    'get_http_filter',
    'get_https_filter',
    'get_dns_filter',
    'get_ssh_filter',
    'get_ping_filter',
]
