"""
Validators for Scapy Framework

This module provides validation functions for IPs, MACs, ports, and other inputs.
"""

import re
import ipaddress
from typing import Union, Tuple, List


def is_valid_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IP address (IPv4 or IPv6).

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IP, False otherwise

    Examples:
        >>> is_valid_ip('192.168.1.1')
        True
        >>> is_valid_ip('999.999.999.999')
        False
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv4(ip: str) -> bool:
    """
    Validate if a string is a valid IPv4 address.

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv4, False otherwise

    Examples:
        >>> is_valid_ipv4('192.168.1.1')
        True
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """
    Validate if a string is a valid IPv6 address.

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv6, False otherwise

    Examples:
        >>> is_valid_ipv6('::1')
        True
    """
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False


def is_valid_mac(mac: str) -> bool:
    """
    Validate if a string is a valid MAC address.

    Args:
        mac: MAC address string to validate

    Returns:
        True if valid MAC, False otherwise

    Examples:
        >>> is_valid_mac('00:11:22:33:44:55')
        True
        >>> is_valid_mac('00-11-22-33-44-55')
        True
    """
    # Accept both colon and hyphen separators
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, mac))


def is_valid_port(port: Union[int, str]) -> bool:
    """
    Validate if a value is a valid port number.

    Args:
        port: Port number to validate (int or string)

    Returns:
        True if valid port, False otherwise

    Examples:
        >>> is_valid_port(80)
        True
        >>> is_valid_port('8080')
        True
        >>> is_valid_port(70000)
        False
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_port_range(port_range: str) -> bool:
    """
    Validate if a string is a valid port range.

    Args:
        port_range: Port range string (e.g., '80-443' or '8080')

    Returns:
        True if valid port range, False otherwise

    Examples:
        >>> is_valid_port_range('80-443')
        True
        >>> is_valid_port_range('8080')
        True
    """
    if '-' in port_range:
        parts = port_range.split('-')
        if len(parts) != 2:
            return False
        start, end = parts
        return is_valid_port(start) and is_valid_port(end) and int(start) <= int(end)
    else:
        return is_valid_port(port_range)


def parse_port_range(port_range: str) -> List[int]:
    """
    Parse a port range string into a list of ports.

    Args:
        port_range: Port range string (e.g., '80-83' or '8080')

    Returns:
        List of port numbers

    Examples:
        >>> parse_port_range('80-83')
        [80, 81, 82, 83]
        >>> parse_port_range('8080')
        [8080]
    """
    if not is_valid_port_range(port_range):
        raise ValueError(f"Invalid port range: {port_range}")

    if '-' in port_range:
        start, end = port_range.split('-')
        return list(range(int(start), int(end) + 1))
    else:
        return [int(port_range)]


def is_valid_cidr(cidr: str) -> bool:
    """
    Validate if a string is valid CIDR notation.

    Args:
        cidr: CIDR notation string (e.g., '192.168.1.0/24')

    Returns:
        True if valid CIDR, False otherwise

    Examples:
        >>> is_valid_cidr('192.168.1.0/24')
        True
        >>> is_valid_cidr('192.168.1.0/33')
        False
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is in a private range.

    Args:
        ip: IP address string

    Returns:
        True if private IP, False otherwise

    Examples:
        >>> is_private_ip('192.168.1.1')
        True
        >>> is_private_ip('8.8.8.8')
        False
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """
    Check if an IP address is public.

    Args:
        ip: IP address string

    Returns:
        True if public IP, False otherwise

    Examples:
        >>> is_public_ip('8.8.8.8')
        True
        >>> is_public_ip('192.168.1.1')
        False
    """
    return is_valid_ip(ip) and not is_private_ip(ip)


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate a target string (IP, CIDR, or hostname).

    Args:
        target: Target string to validate

    Returns:
        Tuple of (is_valid, target_type)
        target_type can be: 'ip', 'cidr', 'hostname', or 'invalid'

    Examples:
        >>> valid, ttype = validate_target('192.168.1.1')
        >>> print(f"Valid: {valid}, Type: {ttype}")
        Valid: True, Type: ip
    """
    # Check if it's an IP
    if is_valid_ip(target):
        return True, 'ip'

    # Check if it's CIDR
    if is_valid_cidr(target):
        return True, 'cidr'

    # Check if it's a valid hostname pattern
    hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    if re.match(hostname_pattern, target):
        return True, 'hostname'

    return False, 'invalid'


def is_valid_interface(interface: str) -> bool:
    """
    Validate if a string is a valid interface name pattern.

    Args:
        interface: Interface name to validate

    Returns:
        True if valid interface name pattern, False otherwise

    Examples:
        >>> is_valid_interface('eth0')
        True
        >>> is_valid_interface('wlan0')
        True
    """
    # Basic validation - alphanumeric with optional dash/underscore
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$'
    return bool(re.match(pattern, interface))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing or replacing invalid characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename

    Examples:
        >>> sanitize_filename('my/file:name*.txt')
        'my_file_name_.txt'
    """
    # Replace invalid characters with underscore
    invalid_chars = r'[<>:"/\\|?*]'
    sanitized = re.sub(invalid_chars, '_', filename)

    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')

    # Ensure filename is not empty
    if not sanitized:
        sanitized = 'unnamed'

    return sanitized


def is_valid_timeout(timeout: Union[int, float]) -> bool:
    """
    Validate if a timeout value is valid.

    Args:
        timeout: Timeout value in seconds

    Returns:
        True if valid timeout, False otherwise

    Examples:
        >>> is_valid_timeout(5)
        True
        >>> is_valid_timeout(-1)
        False
    """
    try:
        timeout_num = float(timeout)
        return timeout_num > 0
    except (ValueError, TypeError):
        return False


def validate_network_range(network: str, allowed_networks: List[str]) -> bool:
    """
    Validate if a network is within allowed network ranges.

    Args:
        network: Network in CIDR notation or IP address
        allowed_networks: List of allowed networks in CIDR notation

    Returns:
        True if network is allowed, False otherwise

    Examples:
        >>> allowed = ['192.168.0.0/16', '10.0.0.0/8']
        >>> validate_network_range('192.168.1.0/24', allowed)
        True
    """
    if not allowed_networks:
        # If no restrictions, all networks are allowed
        return True

    try:
        # Convert target to network
        if '/' not in network:
            target = ipaddress.ip_network(f"{network}/32", strict=False)
        else:
            target = ipaddress.ip_network(network, strict=False)

        # Check if target is within any allowed network
        for allowed_net in allowed_networks:
            allowed = ipaddress.ip_network(allowed_net, strict=False)
            if target.subnet_of(allowed) or target == allowed:
                return True

        return False
    except ValueError:
        return False
