"""
TCP Scanner for Scapy Framework

This module implements TCP SYN scanning (stealth scanning) for port discovery.
"""

from typing import List, Dict, Optional, Callable, Tuple
from scapy.all import IP, TCP, sr1, sr, RandShort, conf
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_ip, is_valid_port, parse_port_range


logger = get_logger(__name__)


class TCPScanner:
    """
    TCP SYN Scanner for port discovery.

    Implements stealth scanning using TCP SYN packets to identify open ports.
    """

    def __init__(self,
                 timeout: float = 0.5,
                 retry: int = 1,
                 max_threads: int = 100,
                 verbose: bool = False):
        """
        Initialize TCP Scanner.

        Args:
            timeout: Timeout for responses (seconds)
            retry: Number of retries
            max_threads: Maximum concurrent threads
            verbose: Enable verbose output
        """
        self.timeout = timeout
        self.retry = retry
        self.max_threads = max_threads
        self.verbose = verbose
        self.results: List[Dict] = []

        # Suppress Scapy warnings if not verbose
        if not verbose:
            conf.verb = 0

        logger.info(f"TCP Scanner initialized (timeout={timeout}s, threads={max_threads})")

    def scan_port(self, target: str, port: int) -> Tuple[int, str]:
        """
        Scan a single port on target.

        Args:
            target: Target IP address
            port: Port number to scan

        Returns:
            Tuple of (port, status) where status is 'open', 'closed', or 'filtered'

        Examples:
            >>> scanner = TCPScanner()
            >>> port, status = scanner.scan_port('192.168.1.1', 80)
            >>> print(f"Port {port}: {status}")
        """
        try:
            # Create SYN packet
            src_port = RandShort()
            ip = IP(dst=target)
            syn = TCP(sport=src_port, dport=port, flags='S')
            packet = ip/syn

            # Send packet and wait for response
            response = sr1(packet, timeout=self.timeout, retry=self.retry, verbose=0)

            if response is None:
                # No response - port filtered or host down
                return port, 'filtered'

            elif response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                flags = tcp_layer.flags

                if flags == 0x12:  # SYN-ACK (open)
                    # Send RST to close connection (stealth)
                    rst = IP(dst=target)/TCP(sport=src_port, dport=port, flags='R')
                    sr1(rst, timeout=0.5, verbose=0)
                    return port, 'open'

                elif flags == 0x14:  # RST-ACK (closed)
                    return port, 'closed'

            return port, 'filtered'

        except PermissionError:
            logger.error("Permission denied. TCP scanning requires root/admin privileges.")
            raise PermissionError("TCP scanning requires elevated privileges")
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return port, 'error'

    def scan_ports(self,
                   target: str,
                   ports: List[int],
                   callback: Optional[Callable[[int, str], None]] = None) -> List[Dict]:
        """
        Scan multiple ports on target.

        Args:
            target: Target IP address
            ports: List of ports to scan
            callback: Optional callback for each port result

        Returns:
            List of dictionaries with port scan results

        Examples:
            >>> scanner = TCPScanner()
            >>> results = scanner.scan_ports('192.168.1.1', [80, 443, 8080])
        """
        if not is_valid_ip(target):
            raise ValueError(f"Invalid target IP: {target}")

        logger.info(f"Starting TCP SYN scan on {target} ({len(ports)} ports)")
        self.results = []

        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, target, port): port
                for port in ports
            }

            # Collect results as they complete
            for future in as_completed(future_to_port):
                try:
                    port, status = future.result()

                    result = {
                        'port': port,
                        'status': status,
                        'timestamp': time.time()
                    }

                    self.results.append(result)

                    if status == 'open':
                        logger.info(f"Port {port}/tcp: {status}")

                    # Call callback if provided
                    if callback:
                        callback(port, status)

                except Exception as e:
                    logger.error(f"Error in port scan: {e}")

        # Sort results by port number
        self.results.sort(key=lambda x: x['port'])

        open_ports = [r for r in self.results if r['status'] == 'open']
        logger.info(f"TCP scan completed. Found {len(open_ports)} open ports")

        return self.results

    def scan_range(self,
                   target: str,
                   port_range: str,
                   callback: Optional[Callable[[int, str], None]] = None) -> List[Dict]:
        """
        Scan a range of ports.

        Args:
            target: Target IP address
            port_range: Port range string (e.g., '1-1000' or '80')
            callback: Optional callback function

        Returns:
            List of scan results

        Examples:
            >>> scanner = TCPScanner()
            >>> results = scanner.scan_range('192.168.1.1', '1-1000')
        """
        ports = parse_port_range(port_range)
        return self.scan_ports(target, ports, callback)

    def scan_common_ports(self,
                         target: str,
                         callback: Optional[Callable[[int, str], None]] = None) -> List[Dict]:
        """
        Scan common ports.

        Args:
            target: Target IP address
            callback: Optional callback function

        Returns:
            List of scan results

        Examples:
            >>> scanner = TCPScanner()
            >>> results = scanner.scan_common_ports('192.168.1.1')
        """
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            8080,  # HTTP-Alt
            8443,  # HTTPS-Alt
        ]

        logger.info(f"Scanning {len(common_ports)} common ports on {target}")
        return self.scan_ports(target, common_ports, callback)

    def get_open_ports(self) -> List[int]:
        """
        Get list of open ports from last scan.

        Returns:
            List of open port numbers
        """
        return [r['port'] for r in self.results if r['status'] == 'open']

    def export_results(self, filename: str, format: str = 'txt') -> None:
        """
        Export scan results to file.

        Args:
            filename: Output filename
            format: Export format ('txt', 'csv', 'json')
        """
        import json
        import csv

        if format == 'txt':
            with open(filename, 'w') as f:
                f.write("TCP Port Scan Results\n")
                f.write("=" * 50 + "\n\n")
                for result in self.results:
                    if result['status'] == 'open':
                        f.write(f"Port {result['port']}/tcp: {result['status']}\n")

        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['port', 'status', 'timestamp'])
                writer.writeheader()
                writer.writerows(self.results)

        elif format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)

        logger.info(f"Results exported to {filename}")


def tcp_syn_scan(target: str,
                 ports: List[int],
                 timeout: float = 0.5,
                 max_threads: int = 100) -> List[Dict]:
    """
    Quick TCP SYN scan function.

    Args:
        target: Target IP address
        ports: List of ports to scan
        timeout: Response timeout
        max_threads: Maximum concurrent threads

    Returns:
        List of scan results

    Examples:
        >>> results = tcp_syn_scan('192.168.1.1', [80, 443])
        >>> open_ports = [r['port'] for r in results if r['status'] == 'open']
    """
    scanner = TCPScanner(timeout=timeout, max_threads=max_threads)
    return scanner.scan_ports(target, ports)
