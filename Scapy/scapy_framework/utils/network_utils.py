"""
Network Utilities for Scapy Framework

This module provides utility functions for network interface operations
and network information gathering.
"""

import socket
import struct
from typing import List, Optional, Dict, Tuple
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, conf
import ipaddress


def get_interfaces() -> List[str]:
    """
    Get list of all network interfaces.

    Returns:
        List of interface names

    Examples:
        >>> interfaces = get_interfaces()
        >>> print(interfaces)
        ['eth0', 'wlan0', 'lo']
    """
    try:
        return get_if_list()
    except Exception as e:
        raise RuntimeError(f"Failed to get network interfaces: {e}")


def get_default_interface() -> str:
    """
    Get the default network interface.

    Returns:
        Default interface name

    Examples:
        >>> iface = get_default_interface()
        >>> print(iface)
        'eth0'
    """
    try:
        return conf.iface
    except Exception as e:
        # Fallback: try to get first non-loopback interface
        interfaces = get_interfaces()
        for iface in interfaces:
            if iface != 'lo' and not iface.startswith('lo'):
                return iface
        return interfaces[0] if interfaces else 'eth0'


def get_interface_ip(interface: Optional[str] = None) -> str:
    """
    Get the IP address of a network interface.

    Args:
        interface: Interface name. If None, uses default interface.

    Returns:
        IP address as string

    Examples:
        >>> ip = get_interface_ip('eth0')
        >>> print(ip)
        '192.168.1.100'
    """
    if interface is None:
        interface = get_default_interface()

    try:
        return get_if_addr(interface)
    except Exception as e:
        raise RuntimeError(f"Failed to get IP address for interface {interface}: {e}")


def get_interface_mac(interface: Optional[str] = None) -> str:
    """
    Get the MAC address of a network interface.

    Args:
        interface: Interface name. If None, uses default interface.

    Returns:
        MAC address as string

    Examples:
        >>> mac = get_interface_mac('eth0')
        >>> print(mac)
        '00:11:22:33:44:55'
    """
    if interface is None:
        interface = get_default_interface()

    try:
        return get_if_hwaddr(interface)
    except Exception as e:
        raise RuntimeError(f"Failed to get MAC address for interface {interface}: {e}")


def get_network_range(ip: str, netmask: str = "255.255.255.0") -> str:
    """
    Calculate network range in CIDR notation from IP and netmask.

    Args:
        ip: IP address
        netmask: Network mask (default: 255.255.255.0)

    Returns:
        Network range in CIDR notation (e.g., '192.168.1.0/24')

    Examples:
        >>> network = get_network_range('192.168.1.100', '255.255.255.0')
        >>> print(network)
        '192.168.1.0/24'
    """
    try:
        # Convert IP and netmask to network
        ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
        netmask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]

        # Calculate network address
        network_int = ip_int & netmask_int
        network_ip = socket.inet_ntoa(struct.pack('!I', network_int))

        # Calculate CIDR prefix length
        prefix_len = bin(netmask_int).count('1')

        return f"{network_ip}/{prefix_len}"
    except Exception as e:
        raise ValueError(f"Invalid IP or netmask: {e}")


def get_interface_network(interface: Optional[str] = None) -> str:
    """
    Get the network range for an interface.

    Args:
        interface: Interface name. If None, uses default interface.

    Returns:
        Network range in CIDR notation

    Examples:
        >>> network = get_interface_network('eth0')
        >>> print(network)
        '192.168.1.0/24'
    """
    ip = get_interface_ip(interface)
    # Assume /24 as default - in production, you'd want to get actual netmask
    return get_network_range(ip, "255.255.255.0")


def is_interface_up(interface: str) -> bool:
    """
    Check if a network interface is up.

    Args:
        interface: Interface name

    Returns:
        True if interface is up, False otherwise

    Examples:
        >>> if is_interface_up('eth0'):
        ...     print('Interface is up')
    """
    try:
        # Try to get IP - if successful, interface is likely up
        ip = get_if_addr(interface)
        return ip != "0.0.0.0" and ip != ""
    except:
        return False


def get_interface_info(interface: Optional[str] = None) -> Dict[str, str]:
    """
    Get comprehensive information about a network interface.

    Args:
        interface: Interface name. If None, uses default interface.

    Returns:
        Dictionary with interface information

    Examples:
        >>> info = get_interface_info('eth0')
        >>> print(info)
        {'name': 'eth0', 'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55', ...}
    """
    if interface is None:
        interface = get_default_interface()

    info = {
        'name': interface,
        'ip': '',
        'mac': '',
        'network': '',
        'is_up': False
    }

    try:
        info['ip'] = get_interface_ip(interface)
        info['mac'] = get_interface_mac(interface)
        info['is_up'] = is_interface_up(interface)
        if info['ip']:
            info['network'] = get_network_range(info['ip'])
    except Exception as e:
        pass

    return info


def cidr_to_ip_range(cidr: str) -> Tuple[str, str]:
    """
    Convert CIDR notation to IP range.

    Args:
        cidr: Network in CIDR notation (e.g., '192.168.1.0/24')

    Returns:
        Tuple of (first_ip, last_ip)

    Examples:
        >>> first, last = cidr_to_ip_range('192.168.1.0/24')
        >>> print(f"{first} - {last}")
        '192.168.1.0 - 192.168.1.255'
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return (str(network.network_address), str(network.broadcast_address))
    except Exception as e:
        raise ValueError(f"Invalid CIDR notation: {e}")


def get_ip_list_from_cidr(cidr: str) -> List[str]:
    """
    Get list of all IP addresses in a CIDR range.

    Args:
        cidr: Network in CIDR notation

    Returns:
        List of IP addresses as strings

    Examples:
        >>> ips = get_ip_list_from_cidr('192.168.1.0/30')
        >>> print(ips)
        ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception as e:
        raise ValueError(f"Invalid CIDR notation: {e}")


def is_ip_in_network(ip: str, network: str) -> bool:
    """
    Check if an IP address is in a network range.

    Args:
        ip: IP address to check
        network: Network in CIDR notation

    Returns:
        True if IP is in network, False otherwise

    Examples:
        >>> is_in = is_ip_in_network('192.168.1.100', '192.168.1.0/24')
        >>> print(is_in)
        True
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in network_obj
    except Exception:
        return False


def get_hostname(ip: str) -> Optional[str]:
    """
    Get hostname for an IP address.

    Args:
        ip: IP address

    Returns:
        Hostname if found, None otherwise

    Examples:
        >>> hostname = get_hostname('8.8.8.8')
        >>> print(hostname)
        'dns.google'
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def get_ip_from_hostname(hostname: str) -> Optional[str]:
    """
    Get IP address from hostname.

    Args:
        hostname: Hostname to resolve

    Returns:
        IP address if found, None otherwise

    Examples:
        >>> ip = get_ip_from_hostname('google.com')
        >>> print(ip)
        '142.250.185.46'
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
