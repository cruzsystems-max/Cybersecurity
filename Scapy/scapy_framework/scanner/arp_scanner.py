"""
ARP Scanner for Scapy Framework

This module implements ARP-based network scanning to discover active hosts
on the local network.
"""

from typing import List, Dict, Optional, Callable
from scapy.all import ARP, Ether, srp, conf
import time

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_cidr, is_valid_ip
from scapy_framework.utils.network_utils import get_interface_ip, get_network_range


logger = get_logger(__name__)


class ARPScanner:
    """
    ARP Scanner for discovering active hosts on local network.

    Uses ARP requests to identify live hosts and their MAC addresses.
    """

    def __init__(self,
                 interface: Optional[str] = None,
                 timeout: float = 1,
                 retry: int = 2,
                 verbose: bool = False):
        """
        Initialize ARP Scanner.

        Args:
            interface: Network interface to use (None = default)
            timeout: Timeout in seconds for ARP responses
            retry: Number of retry attempts
            verbose: Enable verbose output
        """
        self.interface = interface or conf.iface
        self.timeout = timeout
        self.retry = retry
        self.verbose = verbose
        self.results: List[Dict[str, str]] = []

        logger.info(f"ARP Scanner initialized on interface {self.interface}")

    def scan(self,
             target: str,
             callback: Optional[Callable[[Dict[str, str]], None]] = None) -> List[Dict[str, str]]:
        """
        Perform ARP scan on target network.

        Args:
            target: Target network in CIDR notation or single IP
            callback: Optional callback function called for each discovered host

        Returns:
            List of dictionaries containing host information

        Examples:
            >>> scanner = ARPScanner()
            >>> results = scanner.scan('192.168.1.0/24')
            >>> for host in results:
            ...     print(f"{host['ip']} - {host['mac']}")
        """
        logger.info(f"Starting ARP scan on {target}")
        self.results = []

        # Validate target
        if not (is_valid_cidr(target) or is_valid_ip(target)):
            logger.error(f"Invalid target: {target}")
            raise ValueError(f"Invalid target format: {target}")

        # Add /32 if single IP
        if '/' not in target and is_valid_ip(target):
            target = f"{target}/32"

        # Create ARP request
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        logger.debug(f"Sending ARP requests to {target}")

        # Send packets and capture responses
        try:
            answered, unanswered = srp(
                packet,
                timeout=self.timeout,
                retry=self.retry,
                iface=self.interface,
                verbose=self.verbose
            )

            # Process responses
            for sent, received in answered:
                host_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'timestamp': time.time()
                }

                self.results.append(host_info)

                logger.info(f"Host discovered: {host_info['ip']} ({host_info['mac']})")

                # Call callback if provided
                if callback:
                    callback(host_info)

            logger.info(f"ARP scan completed. Found {len(self.results)} hosts")

        except PermissionError:
            logger.error("Permission denied. ARP scanning requires root/admin privileges.")
            raise PermissionError("ARP scanning requires elevated privileges")
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            raise

        return self.results

    def scan_local_network(self,
                          callback: Optional[Callable[[Dict[str, str]], None]] = None) -> List[Dict[str, str]]:
        """
        Scan the local network automatically.

        Determines the local network range and performs ARP scan.

        Args:
            callback: Optional callback function for each discovered host

        Returns:
            List of discovered hosts

        Examples:
            >>> scanner = ARPScanner()
            >>> hosts = scanner.scan_local_network()
        """
        try:
            # Get local IP and determine network
            local_ip = get_interface_ip(self.interface)
            network = get_network_range(local_ip)

            logger.info(f"Auto-detected local network: {network}")

            return self.scan(network, callback)

        except Exception as e:
            logger.error(f"Failed to scan local network: {e}")
            raise

    def get_results(self) -> List[Dict[str, str]]:
        """
        Get scan results.

        Returns:
            List of discovered hosts
        """
        return self.results

    def get_host_count(self) -> int:
        """
        Get number of discovered hosts.

        Returns:
            Number of hosts found
        """
        return len(self.results)

    def is_host_alive(self, ip: str) -> bool:
        """
        Check if a specific host is alive using ARP.

        Args:
            ip: IP address to check

        Returns:
            True if host responds to ARP, False otherwise

        Examples:
            >>> scanner = ARPScanner()
            >>> if scanner.is_host_alive('192.168.1.1'):
            ...     print('Host is alive')
        """
        try:
            results = self.scan(f"{ip}/32")
            return len(results) > 0
        except Exception as e:
            logger.error(f"Failed to check if host {ip} is alive: {e}")
            return False

    def export_results(self, filename: str, format: str = 'txt') -> None:
        """
        Export scan results to file.

        Args:
            filename: Output filename
            format: Export format ('txt', 'csv', 'json')

        Examples:
            >>> scanner.export_results('arp_scan.txt', 'txt')
        """
        import json
        import csv

        if format == 'txt':
            with open(filename, 'w') as f:
                f.write("ARP Scan Results\n")
                f.write("=" * 50 + "\n\n")
                for host in self.results:
                    f.write(f"IP: {host['ip']:<15} MAC: {host['mac']}\n")

        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip', 'mac', 'timestamp'])
                writer.writeheader()
                writer.writerows(self.results)

        elif format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)

        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Results exported to {filename}")


def arp_scan(target: str,
             interface: Optional[str] = None,
             timeout: float = 1,
             verbose: bool = False) -> List[Dict[str, str]]:
    """
    Quick ARP scan function.

    Args:
        target: Target network in CIDR notation
        interface: Network interface to use
        timeout: Response timeout in seconds
        verbose: Enable verbose output

    Returns:
        List of discovered hosts

    Examples:
        >>> hosts = arp_scan('192.168.1.0/24')
        >>> print(f"Found {len(hosts)} hosts")
    """
    scanner = ARPScanner(interface=interface, timeout=timeout, verbose=verbose)
    return scanner.scan(target)
