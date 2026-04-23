"""
TCP Packet Crafting Module for Scapy Framework

This module provides comprehensive TCP packet crafting capabilities for network
security testing and educational purposes.
"""

from typing import Optional, List, Dict, Any
from scapy.all import IP, TCP, send, sr1, sr, conf, Raw
import random
import time

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_ip, is_valid_port

logger = get_logger(__name__)


class TCPCrafter:
    """
    TCP Packet Crafter for custom TCP packet generation.

    Provides methods to craft various TCP packets including SYN, ACK, RST, FIN,
    and custom flag combinations for network testing.
    """

    def __init__(self,
                 src_ip: Optional[str] = None,
                 interface: Optional[str] = None,
                 verbose: bool = False):
        """
        Initialize TCP Crafter.

        Args:
            src_ip: Source IP address (optional, defaults to interface IP)
            interface: Network interface to use
            verbose: Enable verbose output

        Examples:
            >>> crafter = TCPCrafter()
            >>> crafter = TCPCrafter(src_ip='192.168.1.100', verbose=True)
        """
        self.src_ip = src_ip
        self.interface = interface or conf.iface
        self.verbose = verbose

        if not verbose:
            conf.verb = 0

        logger.info(f"TCP Crafter initialized (interface={self.interface})")

    def craft_syn(self,
                  dst_ip: str,
                  dst_port: int,
                  src_port: Optional[int] = None,
                  seq: Optional[int] = None,
                  window: int = 8192) -> IP:
        """
        Craft a TCP SYN packet.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port (random if not specified)
            seq: Sequence number (random if not specified)
            window: TCP window size

        Returns:
            Crafted IP/TCP packet

        Raises:
            ValueError: If IP or port is invalid

        Examples:
            >>> crafter = TCPCrafter()
            >>> syn = crafter.craft_syn('192.168.1.1', 80)
            >>> response = crafter.send_and_receive(syn)
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")
        if not is_valid_port(dst_port):
            raise ValueError(f"Invalid destination port: {dst_port}")

        if src_port is None:
            src_port = random.randint(1024, 65535)
        if seq is None:
            seq = random.randint(1000, 100000)

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        tcp_layer = TCP(
            sport=src_port,
            dport=dst_port,
            flags='S',
            seq=seq,
            window=window
        )

        packet = ip_layer / tcp_layer
        logger.debug(f"Crafted SYN packet: {dst_ip}:{dst_port} (sport={src_port}, seq={seq})")
        return packet

    def craft_ack(self,
                  dst_ip: str,
                  dst_port: int,
                  src_port: int,
                  seq: int,
                  ack: int,
                  window: int = 8192) -> IP:
        """
        Craft a TCP ACK packet.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port
            seq: Sequence number
            ack: Acknowledgment number
            window: TCP window size

        Returns:
            Crafted IP/TCP packet

        Examples:
            >>> crafter = TCPCrafter()
            >>> ack = crafter.craft_ack('192.168.1.1', 80, 12345, 1000, 5001)
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        tcp_layer = TCP(
            sport=src_port,
            dport=dst_port,
            flags='A',
            seq=seq,
            ack=ack,
            window=window
        )

        packet = ip_layer / tcp_layer
        logger.debug(f"Crafted ACK packet: {dst_ip}:{dst_port}")
        return packet

    def craft_syn_ack(self,
                      dst_ip: str,
                      dst_port: int,
                      src_port: int,
                      seq: int,
                      ack: int,
                      window: int = 8192) -> IP:
        """
        Craft a TCP SYN-ACK packet.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port
            seq: Sequence number
            ack: Acknowledgment number
            window: TCP window size

        Returns:
            Crafted IP/TCP packet
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        tcp_layer = TCP(
            sport=src_port,
            dport=dst_port,
            flags='SA',
            seq=seq,
            ack=ack,
            window=window
        )

        packet = ip_layer / tcp_layer
        logger.debug(f"Crafted SYN-ACK packet: {dst_ip}:{dst_port}")
        return packet

    def craft_rst(self,
                  dst_ip: str,
                  dst_port: int,
                  src_port: int,
                  seq: Optional[int] = None) -> IP:
        """
        Craft a TCP RST packet.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port
            seq: Sequence number (random if not specified)

        Returns:
            Crafted IP/TCP packet
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        if seq is None:
            seq = random.randint(1000, 100000)

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        tcp_layer = TCP(
            sport=src_port,
            dport=dst_port,
            flags='R',
            seq=seq
        )

        packet = ip_layer / tcp_layer
        logger.debug(f"Crafted RST packet: {dst_ip}:{dst_port}")
        return packet

    def craft_fin(self,
                  dst_ip: str,
                  dst_port: int,
                  src_port: int,
                  seq: int,
                  ack: int,
                  window: int = 8192) -> IP:
        """
        Craft a TCP FIN packet.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port
            seq: Sequence number
            ack: Acknowledgment number
            window: TCP window size

        Returns:
            Crafted IP/TCP packet
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        tcp_layer = TCP(
            sport=src_port,
            dport=dst_port,
            flags='F',
            seq=seq,
            ack=ack,
            window=window
        )

        packet = ip_layer / tcp_layer
        logger.debug(f"Crafted FIN packet: {dst_ip}:{dst_port}")
        return packet

    def craft_custom(self,
                     dst_ip: str,
                     dst_port: int,
                     src_port: Optional[int] = None,
                     flags: str = 'S',
                     seq: Optional[int] = None,
                     ack: Optional[int] = None,
                     window: int = 8192,
                     payload: Optional[str] = None) -> IP:
        """
        Craft a custom TCP packet with specified parameters.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port (random if not specified)
            flags: TCP flags (e.g., 'S', 'SA', 'PA', 'F')
            seq: Sequence number (random if not specified)
            ack: Acknowledgment number
            window: TCP window size
            payload: Optional payload data

        Returns:
            Crafted IP/TCP packet

        Examples:
            >>> crafter = TCPCrafter()
            >>> packet = crafter.craft_custom('192.168.1.1', 80, flags='PA',
            ...                               payload='GET / HTTP/1.1\\r\\n\\r\\n')
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")
        if not is_valid_port(dst_port):
            raise ValueError(f"Invalid destination port: {dst_port}")

        if src_port is None:
            src_port = random.randint(1024, 65535)
        if seq is None:
            seq = random.randint(1000, 100000)

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        tcp_kwargs = {
            'sport': src_port,
            'dport': dst_port,
            'flags': flags,
            'seq': seq,
            'window': window
        }

        if ack is not None:
            tcp_kwargs['ack'] = ack

        tcp_layer = TCP(**tcp_kwargs)
        packet = ip_layer / tcp_layer

        if payload:
            packet = packet / Raw(load=payload)

        logger.debug(f"Crafted custom TCP packet: {dst_ip}:{dst_port} (flags={flags})")
        return packet

    def send_packet(self, packet: IP, count: int = 1) -> None:
        """
        Send a crafted packet.

        Args:
            packet: Packet to send
            count: Number of times to send

        Examples:
            >>> crafter = TCPCrafter()
            >>> syn = crafter.craft_syn('192.168.1.1', 80)
            >>> crafter.send_packet(syn)
        """
        try:
            logger.info(f"Sending {count} packet(s)...")
            send(packet, iface=self.interface, count=count, verbose=self.verbose)
            logger.info("Packet(s) sent successfully")
        except PermissionError:
            logger.error("Permission denied. Packet sending requires root/admin privileges.")
            raise PermissionError("Packet sending requires elevated privileges")
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            raise

    def send_and_receive(self, packet: IP, timeout: int = 2) -> Optional[IP]:
        """
        Send a packet and wait for response.

        Args:
            packet: Packet to send
            timeout: Timeout in seconds

        Returns:
            Response packet or None

        Examples:
            >>> crafter = TCPCrafter()
            >>> syn = crafter.craft_syn('192.168.1.1', 80)
            >>> response = crafter.send_and_receive(syn)
            >>> if response:
            ...     print(response.summary())
        """
        try:
            logger.info("Sending packet and waiting for response...")
            response = sr1(packet, iface=self.interface, timeout=timeout, verbose=self.verbose)

            if response:
                logger.info(f"Received response: {response.summary()}")
            else:
                logger.info("No response received")

            return response

        except PermissionError:
            logger.error("Permission denied. Packet operations require root/admin privileges.")
            raise PermissionError("Packet operations require elevated privileges")
        except Exception as e:
            logger.error(f"Error in send/receive: {e}")
            raise

    def send_and_receive_multiple(self,
                                   packet: IP,
                                   timeout: int = 2,
                                   count: int = 1) -> List[IP]:
        """
        Send packet(s) and receive multiple responses.

        Args:
            packet: Packet to send
            timeout: Timeout in seconds
            count: Number of packets to send

        Returns:
            List of response packets
        """
        try:
            logger.info(f"Sending {count} packet(s) and waiting for responses...")
            answered, unanswered = sr(packet,
                                      iface=self.interface,
                                      timeout=timeout,
                                      verbose=self.verbose,
                                      count=count)

            responses = [rcv for snd, rcv in answered]
            logger.info(f"Received {len(responses)} response(s)")

            return responses

        except PermissionError:
            logger.error("Permission denied. Packet operations require root/admin privileges.")
            raise PermissionError("Packet operations require elevated privileges")
        except Exception as e:
            logger.error(f"Error in send/receive multiple: {e}")
            raise

    def perform_handshake(self,
                          dst_ip: str,
                          dst_port: int,
                          src_port: Optional[int] = None,
                          timeout: int = 2) -> Dict[str, Any]:
        """
        Perform a complete TCP three-way handshake.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port (random if not specified)
            timeout: Response timeout

        Returns:
            Dictionary with handshake results

        Examples:
            >>> crafter = TCPCrafter()
            >>> result = crafter.perform_handshake('192.168.1.1', 80)
            >>> if result['success']:
            ...     print("Handshake successful!")
        """
        if src_port is None:
            src_port = random.randint(1024, 65535)

        seq_initial = random.randint(1000, 100000)

        result = {
            'success': False,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'steps': []
        }

        try:
            # Step 1: Send SYN
            logger.info(f"Handshake Step 1: Sending SYN to {dst_ip}:{dst_port}")
            syn = self.craft_syn(dst_ip, dst_port, src_port, seq_initial)
            syn_ack = self.send_and_receive(syn, timeout)

            if not syn_ack or not syn_ack.haslayer(TCP):
                result['steps'].append({'step': 1, 'status': 'failed', 'reason': 'No SYN-ACK received'})
                return result

            tcp_layer = syn_ack.getlayer(TCP)
            if tcp_layer.flags != 0x12:  # SYN-ACK
                result['steps'].append({'step': 1, 'status': 'failed', 'reason': 'Invalid flags in response'})
                return result

            result['steps'].append({'step': 1, 'status': 'success', 'packet': 'SYN-ACK received'})

            # Step 2: Send ACK
            logger.info("Handshake Step 2: Sending ACK")
            ack_seq = seq_initial + 1
            ack_num = tcp_layer.seq + 1

            ack = self.craft_ack(dst_ip, dst_port, src_port, ack_seq, ack_num)
            self.send_packet(ack)

            result['steps'].append({'step': 2, 'status': 'success', 'packet': 'ACK sent'})

            # Step 3: Send RST to close connection
            logger.info("Handshake Step 3: Sending RST to close")
            rst = self.craft_rst(dst_ip, dst_port, src_port, ack_seq)
            self.send_packet(rst)

            result['steps'].append({'step': 3, 'status': 'success', 'packet': 'RST sent'})
            result['success'] = True

            logger.info("TCP handshake completed successfully")

        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            result['error'] = str(e)

        return result


def craft_tcp_packet(dst_ip: str,
                     dst_port: int,
                     flags: str = 'S',
                     src_port: Optional[int] = None,
                     payload: Optional[str] = None) -> IP:
    """
    Quick helper function to craft a TCP packet.

    Args:
        dst_ip: Destination IP address
        dst_port: Destination port
        flags: TCP flags (default: 'S' for SYN)
        src_port: Source port (random if not specified)
        payload: Optional payload data

    Returns:
        Crafted IP/TCP packet

    Examples:
        >>> syn = craft_tcp_packet('192.168.1.1', 80)
        >>> psh_ack = craft_tcp_packet('192.168.1.1', 80, flags='PA',
        ...                            payload='GET / HTTP/1.1\\r\\n\\r\\n')
    """
    crafter = TCPCrafter()
    return crafter.craft_custom(dst_ip, dst_port, src_port, flags, payload=payload)
