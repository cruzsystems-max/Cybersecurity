"""
Utilities module for Scapy Framework

This module provides utility functions for network operations,
packet manipulation, and input validation.
"""

from .network_utils import (
    get_interfaces,
    get_default_interface,
    get_interface_ip,
    get_interface_mac,
    get_network_range,
    is_interface_up
)

from .packet_utils import (
    packet_summary,
    extract_layer,
    has_layer,
    get_packet_size,
    packet_to_dict,
    analyze_packet
)

from .validators import (
    is_valid_ip,
    is_valid_mac,
    is_valid_port,
    is_valid_port_range,
    is_valid_cidr,
    is_private_ip,
    validate_target
)

__all__ = [
    # Network utils
    'get_interfaces',
    'get_default_interface',
    'get_interface_ip',
    'get_interface_mac',
    'get_network_range',
    'is_interface_up',
    # Packet utils
    'packet_summary',
    'extract_layer',
    'has_layer',
    'get_packet_size',
    'packet_to_dict',
    'analyze_packet',
    # Validators
    'is_valid_ip',
    'is_valid_mac',
    'is_valid_port',
    'is_valid_port_range',
    'is_valid_cidr',
    'is_private_ip',
    'validate_target',
]
