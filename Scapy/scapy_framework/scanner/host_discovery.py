"""
Host Discovery for Scapy Framework

This module implements multiple techniques for discovering active hosts
on a network.
"""

from typing import List, Dict, Optional, Set
from scapy.all import IP, ICMP, ARP, Ether, sr1, srp, conf
import time

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_cidr, is_valid_ip
from scapy_framework.utils.network_utils import get_ip_list_from_cidr
from scapy_framework.scanner.arp_scanner import ARPScanner


logger = get_logger(__name__)


class HostDiscovery:
    """
    Host Discovery using multiple techniques.

    Combines ARP scanning, ICMP ping, and TCP probing for comprehensive
    host discovery.
    """

    def __init__(self,
                 interface: Optional[str] = None,
                 timeout: float = 1,
                 verbose: bool = False):
        """
        Initialize Host Discovery.

        Args:
            interface: Network interface to use
            timeout: Response timeout in seconds
            verbose: Enable verbose output
        """
        self.interface = interface or conf.iface
        self.timeout = timeout
        self.verbose = verbose
        self.discovered_hosts: Set[str] = set()
        self.results: List[Dict] = []

        logger.info("Host Discovery initialized")

    def arp_discovery(self, target: str) -> List[str]:
        """
        Discover hosts using ARP scanning.

        Args:
            target: Target network in CIDR notation

        Returns:
            List of discovered IP addresses

        Examples:
            >>> discovery = HostDiscovery()
            >>> hosts = discovery.arp_discovery('192.168.1.0/24')
        """
        logger.info(f"ARP discovery on {target}")

        try:
            scanner = ARPScanner(
                interface=self.interface,
                timeout=self.timeout,
                verbose=self.verbose
            )
            results = scanner.scan(target)

            hosts = [r['ip'] for r in results]
            self.discovered_hosts.update(hosts)

            logger.info(f"ARP discovery found {len(hosts)} hosts")
            return hosts

        except Exception as e:
            logger.error(f"ARP discovery failed: {e}")
            return []

    def icmp_discovery(self, target: str) -> List[str]:
        """
        Discover hosts using ICMP ping.

        Args:
            target: Target network in CIDR notation or single IP

        Returns:
            List of discovered IP addresses

        Examples:
            >>> discovery = HostDiscovery()
            >>> hosts = discovery.icmp_discovery('192.168.1.0/24')
        """
        logger.info(f"ICMP discovery on {target}")

        discovered = []

        try:
            # Get list of IPs to scan
            if '/' in target:
                ip_list = get_ip_list_from_cidr(target)
            else:
                ip_list = [target]

            # Ping each IP
            for ip in ip_list:
                if self._icmp_ping(ip):
                    discovered.append(ip)
                    self.discovered_hosts.add(ip)

            logger.info(f"ICMP discovery found {len(discovered)} hosts")
            return discovered

        except Exception as e:
            logger.error(f"ICMP discovery failed: {e}")
            return []

    def _icmp_ping(self, ip: str) -> bool:
        """
        Send ICMP ping to a single host.

        Args:
            ip: Target IP address

        Returns:
            True if host responds, False otherwise
        """
        try:
            packet = IP(dst=ip)/ICMP()
            response = sr1(packet, timeout=self.timeout, verbose=0)

            if response is not None and response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 0:  # Echo reply
                    logger.debug(f"Host {ip} is alive (ICMP)")
                    return True

            return False

        except Exception as e:
            logger.debug(f"ICMP ping failed for {ip}: {e}")
            return False

    def discover(self,
                 target: str,
                 methods: Optional[List[str]] = None) -> List[Dict]:
        """
        Discover hosts using multiple methods.

        Args:
            target: Target network in CIDR notation
            methods: List of methods to use ('arp', 'icmp')
                    Default: ['arp', 'icmp']

        Returns:
            List of discovered hosts with details

        Examples:
            >>> discovery = HostDiscovery()
            >>> hosts = discovery.discover('192.168.1.0/24', methods=['arp', 'icmp'])
        """
        if methods is None:
            methods = ['arp', 'icmp']

        logger.info(f"Starting host discovery on {target} using methods: {methods}")

        self.discovered_hosts.clear()
        self.results = []

        # ARP discovery
        if 'arp' in methods:
            try:
                self.arp_discovery(target)
            except Exception as e:
                logger.warning(f"ARP discovery failed: {e}")

        # ICMP discovery
        if 'icmp' in methods:
            try:
                self.icmp_discovery(target)
            except Exception as e:
                logger.warning(f"ICMP discovery failed: {e}")

        # Compile results
        for ip in self.discovered_hosts:
            self.results.append({
                'ip': ip,
                'status': 'alive',
                'timestamp': time.time()
            })

        logger.info(f"Host discovery completed. Found {len(self.discovered_hosts)} unique hosts")
        return self.results

    def get_discovered_hosts(self) -> List[str]:
        """
        Get list of discovered host IPs.

        Returns:
            List of IP addresses
        """
        return list(self.discovered_hosts)

    def get_host_count(self) -> int:
        """
        Get number of discovered hosts.

        Returns:
            Number of hosts
        """
        return len(self.discovered_hosts)

    def is_host_alive(self, ip: str, method: str = 'icmp') -> bool:
        """
        Check if a specific host is alive.

        Args:
            ip: IP address to check
            method: Method to use ('icmp' or 'arp')

        Returns:
            True if host is alive, False otherwise

        Examples:
            >>> discovery = HostDiscovery()
            >>> if discovery.is_host_alive('192.168.1.1'):
            ...     print('Host is alive')
        """
        if not is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip}")

        if method == 'icmp':
            return self._icmp_ping(ip)
        elif method == 'arp':
            scanner = ARPScanner(interface=self.interface, timeout=self.timeout)
            return scanner.is_host_alive(ip)
        else:
            raise ValueError(f"Unknown method: {method}")

    def export_results(self, filename: str, format: str = 'txt') -> None:
        """
        Export discovery results to file.

        Args:
            filename: Output filename
            format: Export format ('txt', 'csv', 'json')
        """
        import json
        import csv

        if format == 'txt':
            with open(filename, 'w') as f:
                f.write("Host Discovery Results\n")
                f.write("=" * 50 + "\n\n")
                for host in sorted(self.discovered_hosts):
                    f.write(f"{host}\n")

        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Address'])
                for host in sorted(self.discovered_hosts):
                    writer.writerow([host])

        elif format == 'json':
            with open(filename, 'w') as f:
                json.dump(sorted(list(self.discovered_hosts)), f, indent=2)

        logger.info(f"Results exported to {filename}")


def discover_hosts(target: str,
                   methods: Optional[List[str]] = None,
                   timeout: float = 1) -> List[str]:
    """
    Quick host discovery function.

    Args:
        target: Target network in CIDR notation
        methods: Discovery methods to use
        timeout: Response timeout in seconds

    Returns:
        List of discovered host IPs

    Examples:
        >>> hosts = discover_hosts('192.168.1.0/24')
        >>> print(f"Found {len(hosts)} hosts")
    """
    discovery = HostDiscovery(timeout=timeout)
    results = discovery.discover(target, methods)
    return [r['ip'] for r in results]
