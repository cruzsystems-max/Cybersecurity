"""
Packet Replay Attack Module for Scapy Framework

⚠️  CRITICAL ETHICAL WARNING ⚠️
This module is for EDUCATIONAL and AUTHORIZED SECURITY TESTING ONLY.
Unauthorized packet replay is ILLEGAL and can result in criminal prosecution.

Only use in:
- Controlled laboratory environments
- Authorized penetration testing engagements
- Educational demonstrations with proper authorization
- Your own network infrastructure

The authors assume NO responsibility for misuse of this tool.
"""

from typing import Optional, List, Dict, Any, Callable
from scapy.all import sendp, send, rdpcap, wrpcap, Packet, conf
from pathlib import Path
import time
import threading

from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)


class PacketReplayer:
    """
    Packet Replay attack implementation.

    Replays previously captured network packets for testing network behavior,
    IDS/IPS testing, or security research.

    ⚠️  WARNING: Use only with explicit authorization!
    """

    def __init__(self, interface: Optional[str] = None, verbose: bool = False):
        """
        Initialize Packet Replayer.

        Args:
            interface: Network interface to use
            verbose: Enable verbose output

        Examples:
            >>> replayer = PacketReplayer(interface='eth0')
        """
        self.interface = interface or conf.iface
        self.verbose = verbose
        self.packets: List[Packet] = []
        self.is_replaying = False
        self.replay_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            'packets_loaded': 0,
            'packets_sent': 0,
            'replay_count': 0,
            'start_time': None,
            'end_time': None,
        }

        logger.warning("⚠️  Packet Replayer initialized - ENSURE AUTHORIZATION BEFORE USE!")
        logger.info(f"Using interface: {self.interface}")

    def load_pcap(self, pcap_file: str) -> int:
        """
        Load packets from PCAP file.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            Number of packets loaded

        Raises:
            FileNotFoundError: If PCAP file doesn't exist

        Examples:
            >>> replayer.load_pcap('capture.pcap')
            >>> print(f"Loaded {replayer.get_packet_count()} packets")
        """
        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        try:
            self.packets = rdpcap(str(pcap_path))
            self.stats['packets_loaded'] = len(self.packets)
            logger.info(f"Loaded {len(self.packets)} packets from {pcap_file}")
            return len(self.packets)
        except Exception as e:
            logger.error(f"Failed to load PCAP file: {e}")
            raise

    def load_packets(self, packets: List[Packet]) -> int:
        """
        Load packets from a list.

        Args:
            packets: List of Packet objects

        Returns:
            Number of packets loaded

        Examples:
            >>> from scapy.all import IP, TCP
            >>> packets = [IP(dst='192.168.1.1')/TCP(dport=80) for _ in range(10)]
            >>> replayer.load_packets(packets)
        """
        self.packets = packets.copy()
        self.stats['packets_loaded'] = len(self.packets)
        logger.info(f"Loaded {len(self.packets)} packets from list")
        return len(self.packets)

    def get_packet_count(self) -> int:
        """
        Get number of loaded packets.

        Returns:
            Packet count
        """
        return len(self.packets)

    def get_packets(self) -> List[Packet]:
        """
        Get loaded packets.

        Returns:
            List of packets
        """
        return self.packets.copy()

    def filter_packets(self, filter_func: Callable[[Packet], bool]) -> int:
        """
        Filter loaded packets.

        Args:
            filter_func: Function that returns True for packets to keep

        Returns:
            Number of packets after filtering

        Examples:
            >>> # Keep only TCP packets
            >>> replayer.filter_packets(lambda p: p.haslayer(TCP))
        """
        original_count = len(self.packets)
        self.packets = [pkt for pkt in self.packets if filter_func(pkt)]
        removed = original_count - len(self.packets)

        logger.info(f"Filtered packets: {original_count} -> {len(self.packets)} (removed {removed})")
        return len(self.packets)

    def replay(self,
               count: int = 1,
               interval: float = 0,
               loop: bool = False,
               realtime: bool = False,
               layer2: bool = False) -> None:
        """
        Replay loaded packets.

        Args:
            count: Number of times to replay all packets
            interval: Delay between packets in seconds
            loop: Loop indefinitely (overrides count)
            realtime: Preserve original timing between packets
            layer2: Send at layer 2 (Ethernet) instead of layer 3 (IP)

        Examples:
            >>> replayer.load_pcap('capture.pcap')
            >>> replayer.replay(count=3, interval=0.1)
        """
        if not self.packets:
            logger.warning("No packets loaded to replay")
            return

        logger.critical("⚠️  STARTING PACKET REPLAY ATTACK ⚠️")
        logger.warning(f"Replaying {len(self.packets)} packets")
        logger.warning("ENSURE YOU HAVE AUTHORIZATION!")

        self.stats['start_time'] = time.time()
        self.stats['packets_sent'] = 0
        self.stats['replay_count'] = 0
        self.is_replaying = True

        send_func = sendp if layer2 else send

        try:
            iteration = 0
            while self.is_replaying and (loop or iteration < count):
                iteration += 1
                self.stats['replay_count'] = iteration

                logger.info(f"Replay iteration {iteration}{' (loop mode)' if loop else f'/{count}'}")

                prev_time = None
                for i, pkt in enumerate(self.packets):
                    if not self.is_replaying:
                        break

                    # Send packet
                    send_func(pkt, iface=self.interface, verbose=self.verbose)
                    self.stats['packets_sent'] += 1

                    if self.verbose:
                        logger.debug(f"Sent packet {i+1}/{len(self.packets)}: {pkt.summary()}")

                    # Handle timing
                    if realtime and hasattr(pkt, 'time'):
                        # Preserve original timing
                        if prev_time is not None:
                            delay = pkt.time - prev_time
                            if delay > 0:
                                time.sleep(delay)
                        prev_time = pkt.time
                    elif interval > 0:
                        # Fixed interval
                        time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Packet replay interrupted by user")
        except PermissionError:
            logger.error("Permission denied. Packet replay requires root/admin privileges.")
            raise
        except Exception as e:
            logger.error(f"Packet replay failed: {e}")
            raise
        finally:
            self.is_replaying = False
            self.stats['end_time'] = time.time()
            logger.info(f"Packet replay stopped. Sent {self.stats['packets_sent']} packets "
                       f"in {self.stats['replay_count']} iteration(s)")

    def replay_background(self,
                          count: int = 1,
                          interval: float = 0,
                          loop: bool = False,
                          realtime: bool = False,
                          layer2: bool = False) -> None:
        """
        Replay packets in background thread.

        Args:
            count: Number of times to replay
            interval: Delay between packets
            loop: Loop indefinitely
            realtime: Preserve original timing
            layer2: Send at layer 2

        Examples:
            >>> replayer.replay_background(loop=True, interval=0.1)
            >>> # Do other work...
            >>> replayer.stop()
        """
        if self.is_replaying:
            logger.warning("Replay already running")
            return

        self.replay_thread = threading.Thread(
            target=lambda: self.replay(count, interval, loop, realtime, layer2),
            daemon=True
        )
        self.replay_thread.start()
        logger.info("Packet replay started in background")

    def stop(self) -> None:
        """
        Stop packet replay.

        Examples:
            >>> replayer.stop()
        """
        if self.is_replaying:
            logger.info("Stopping packet replay...")
            self.is_replaying = False

            if self.replay_thread:
                self.replay_thread.join(timeout=5)

            logger.info("Packet replay stopped")
        else:
            logger.warning("Packet replay is not running")

    def replay_single(self, packet: Packet, count: int = 1, interval: float = 0) -> None:
        """
        Replay a single packet multiple times.

        Args:
            packet: Packet to replay
            count: Number of times to send
            interval: Delay between sends

        Examples:
            >>> from scapy.all import IP, ICMP
            >>> ping = IP(dst='8.8.8.8')/ICMP()
            >>> replayer.replay_single(ping, count=10)
        """
        logger.info(f"Replaying single packet {count} times")

        try:
            for i in range(count):
                send(packet, iface=self.interface, verbose=self.verbose)
                self.stats['packets_sent'] += 1

                if interval > 0 and i < count - 1:
                    time.sleep(interval)

            logger.info(f"Sent packet {count} times")

        except Exception as e:
            logger.error(f"Failed to replay single packet: {e}")
            raise

    def replay_modified(self,
                        modify_func: Callable[[Packet], Packet],
                        count: int = 1,
                        interval: float = 0) -> None:
        """
        Replay packets with modifications.

        Args:
            modify_func: Function to modify each packet before sending
            count: Number of replay iterations
            interval: Delay between packets

        Examples:
            >>> def change_dst(pkt):
            ...     if pkt.haslayer(IP):
            ...         pkt[IP].dst = '192.168.1.100'
            ...     return pkt
            >>> replayer.replay_modified(change_dst, count=1)
        """
        if not self.packets:
            logger.warning("No packets loaded to replay")
            return

        logger.info(f"Replaying {len(self.packets)} modified packets")

        try:
            for _ in range(count):
                for pkt in self.packets:
                    modified_pkt = modify_func(pkt.copy())
                    send(modified_pkt, iface=self.interface, verbose=self.verbose)
                    self.stats['packets_sent'] += 1

                    if interval > 0:
                        time.sleep(interval)

            logger.info(f"Completed modified packet replay")

        except Exception as e:
            logger.error(f"Failed to replay modified packets: {e}")
            raise

    def save_packets(self, filename: str) -> None:
        """
        Save loaded packets to PCAP file.

        Args:
            filename: Output PCAP filename

        Examples:
            >>> replayer.filter_packets(lambda p: p.haslayer(TCP))
            >>> replayer.save_packets('filtered.pcap')
        """
        if not self.packets:
            logger.warning("No packets to save")
            return

        try:
            wrpcap(filename, self.packets)
            logger.info(f"Saved {len(self.packets)} packets to {filename}")
        except Exception as e:
            logger.error(f"Failed to save packets: {e}")
            raise

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get replay statistics.

        Returns:
            Dictionary with statistics

        Examples:
            >>> stats = replayer.get_statistics()
            >>> print(f"Packets sent: {stats['packets_sent']}")
        """
        duration = 0
        if self.stats['start_time'] and self.stats['end_time']:
            duration = self.stats['end_time'] - self.stats['start_time']

        return {
            'packets_loaded': self.stats['packets_loaded'],
            'packets_sent': self.stats['packets_sent'],
            'replay_count': self.stats['replay_count'],
            'duration': duration,
            'packets_per_second': self.stats['packets_sent'] / duration if duration > 0 else 0,
            'is_running': self.is_replaying,
        }

    def print_statistics(self) -> None:
        """
        Print replay statistics to console.

        Examples:
            >>> replayer.print_statistics()
        """
        stats = self.get_statistics()

        print("\n" + "=" * 60)
        print("PACKET REPLAY STATISTICS")
        print("=" * 60)
        print(f"Packets Loaded:    {stats['packets_loaded']}")
        print(f"Packets Sent:      {stats['packets_sent']}")
        print(f"Replay Count:      {stats['replay_count']}")
        print(f"Duration:          {stats['duration']:.2f} seconds")
        print(f"Packets/sec:       {stats['packets_per_second']:.2f}")
        print(f"Status:            {'Running' if stats['is_running'] else 'Stopped'}")
        print("=" * 60 + "\n")


def replay_pcap(pcap_file: str,
                interface: Optional[str] = None,
                count: int = 1,
                interval: float = 0,
                realtime: bool = False) -> None:
    """
    Quick packet replay function.

    Args:
        pcap_file: PCAP file to replay
        interface: Network interface
        count: Number of replay iterations
        interval: Delay between packets
        realtime: Preserve original timing

    Examples:
        >>> replay_pcap('capture.pcap', count=3, interval=0.1)
    """
    replayer = PacketReplayer(interface=interface, verbose=True)
    replayer.load_pcap(pcap_file)

    try:
        replayer.replay(count=count, interval=interval, realtime=realtime)
    finally:
        replayer.print_statistics()
