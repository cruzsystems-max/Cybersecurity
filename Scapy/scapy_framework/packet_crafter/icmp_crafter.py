"""
ICMP Packet Crafting Module for Scapy Framework

This module provides comprehensive ICMP packet crafting capabilities for network
security testing and educational purposes.
"""

from typing import Optional, List, Dict, Any
from scapy.all import IP, ICMP, send, sr1, sr, conf, Raw
import random
import time

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_ip

logger = get_logger(__name__)


class ICMPCrafter:
    """
    ICMP Packet Crafter for custom ICMP packet generation.

    Provides methods to craft various ICMP packets including echo requests (ping),
    timestamp requests, destination unreachable, and other ICMP types.
    """

    def __init__(self,
                 src_ip: Optional[str] = None,
                 interface: Optional[str] = None,
                 verbose: bool = False):
        """
        Initialize ICMP Crafter.

        Args:
            src_ip: Source IP address (optional, defaults to interface IP)
            interface: Network interface to use
            verbose: Enable verbose output

        Examples:
            >>> crafter = ICMPCrafter()
            >>> crafter = ICMPCrafter(src_ip='192.168.1.100', verbose=True)
        """
        self.src_ip = src_ip
        self.interface = interface or conf.iface
        self.verbose = verbose

        if not verbose:
            conf.verb = 0

        logger.info(f"ICMP Crafter initialized (interface={self.interface})")

    def craft_ping(self,
                   dst_ip: str,
                   id: Optional[int] = None,
                   seq: int = 1,
                   payload_size: int = 56) -> IP:
        """
        Craft an ICMP Echo Request (ping) packet.

        Args:
            dst_ip: Destination IP address
            id: ICMP ID (random if not specified)
            seq: Sequence number
            payload_size: Size of payload in bytes

        Returns:
            Crafted IP/ICMP packet

        Raises:
            ValueError: If IP is invalid

        Examples:
            >>> crafter = ICMPCrafter()
            >>> ping = crafter.craft_ping('8.8.8.8')
            >>> response = crafter.send_and_receive(ping)
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        if id is None:
            id = random.randint(1, 65535)

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        icmp_layer = ICMP(type=8, code=0, id=id, seq=seq)

        # Add payload
        payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
        packet = ip_layer / icmp_layer / Raw(load=payload)

        logger.debug(f"Crafted ICMP Echo Request: {dst_ip} (id={id}, seq={seq})")
        return packet

    def craft_echo_reply(self,
                         dst_ip: str,
                         id: int,
                         seq: int,
                         payload: Optional[bytes] = None) -> IP:
        """
        Craft an ICMP Echo Reply packet.

        Args:
            dst_ip: Destination IP address
            id: ICMP ID
            seq: Sequence number
            payload: Optional payload data

        Returns:
            Crafted IP/ICMP packet
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        icmp_layer = ICMP(type=0, code=0, id=id, seq=seq)
        packet = ip_layer / icmp_layer

        if payload:
            packet = packet / Raw(load=payload)

        logger.debug(f"Crafted ICMP Echo Reply: {dst_ip} (id={id}, seq={seq})")
        return packet

    def craft_dest_unreachable(self,
                               dst_ip: str,
                               code: int = 3,
                               original_packet: Optional[IP] = None) -> IP:
        """
        Craft an ICMP Destination Unreachable packet.

        Args:
            dst_ip: Destination IP address
            code: ICMP code (0=net unreachable, 1=host unreachable, 3=port unreachable)
            original_packet: Original packet that triggered the error

        Returns:
            Crafted IP/ICMP packet

        Examples:
            >>> crafter = ICMPCrafter()
            >>> unreachable = crafter.craft_dest_unreachable('192.168.1.1', code=1)
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        icmp_layer = ICMP(type=3, code=code)
        packet = ip_layer / icmp_layer

        if original_packet:
            packet = packet / Raw(load=bytes(original_packet)[:28])

        logger.debug(f"Crafted ICMP Dest Unreachable: {dst_ip} (code={code})")
        return packet

    def craft_time_exceeded(self,
                            dst_ip: str,
                            code: int = 0,
                            original_packet: Optional[IP] = None) -> IP:
        """
        Craft an ICMP Time Exceeded packet.

        Args:
            dst_ip: Destination IP address
            code: ICMP code (0=TTL exceeded, 1=fragment reassembly time exceeded)
            original_packet: Original packet that triggered the error

        Returns:
            Crafted IP/ICMP packet
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        icmp_layer = ICMP(type=11, code=code)
        packet = ip_layer / icmp_layer

        if original_packet:
            packet = packet / Raw(load=bytes(original_packet)[:28])

        logger.debug(f"Crafted ICMP Time Exceeded: {dst_ip} (code={code})")
        return packet

    def craft_redirect(self,
                       dst_ip: str,
                       gateway: str,
                       code: int = 0,
                       original_packet: Optional[IP] = None) -> IP:
        """
        Craft an ICMP Redirect packet.

        Args:
            dst_ip: Destination IP address
            gateway: Gateway IP address to redirect to
            code: ICMP code (0=network, 1=host, 2=TOS network, 3=TOS host)
            original_packet: Original packet that triggered the redirect

        Returns:
            Crafted IP/ICMP packet
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")
        if not is_valid_ip(gateway):
            raise ValueError(f"Invalid gateway IP: {gateway}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        icmp_layer = ICMP(type=5, code=code, gw=gateway)
        packet = ip_layer / icmp_layer

        if original_packet:
            packet = packet / Raw(load=bytes(original_packet)[:28])

        logger.debug(f"Crafted ICMP Redirect: {dst_ip} -> {gateway} (code={code})")
        return packet

    def craft_timestamp(self,
                        dst_ip: str,
                        id: Optional[int] = None,
                        seq: int = 1) -> IP:
        """
        Craft an ICMP Timestamp Request packet.

        Args:
            dst_ip: Destination IP address
            id: ICMP ID (random if not specified)
            seq: Sequence number

        Returns:
            Crafted IP/ICMP packet
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        if id is None:
            id = random.randint(1, 65535)

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        icmp_layer = ICMP(type=13, code=0, id=id, seq=seq)
        packet = ip_layer / icmp_layer

        logger.debug(f"Crafted ICMP Timestamp Request: {dst_ip} (id={id}, seq={seq})")
        return packet

    def craft_custom(self,
                     dst_ip: str,
                     type: int,
                     code: int = 0,
                     **kwargs) -> IP:
        """
        Craft a custom ICMP packet with specified type and code.

        Args:
            dst_ip: Destination IP address
            type: ICMP type
            code: ICMP code
            **kwargs: Additional ICMP layer arguments

        Returns:
            Crafted IP/ICMP packet

        Examples:
            >>> crafter = ICMPCrafter()
            >>> packet = crafter.craft_custom('192.168.1.1', type=8, code=0, id=1234)
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        icmp_layer = ICMP(type=type, code=code, **kwargs)
        packet = ip_layer / icmp_layer

        logger.debug(f"Crafted custom ICMP packet: {dst_ip} (type={type}, code={code})")
        return packet

    def send_packet(self, packet: IP, count: int = 1) -> None:
        """
        Send a crafted ICMP packet.

        Args:
            packet: Packet to send
            count: Number of times to send

        Examples:
            >>> crafter = ICMPCrafter()
            >>> ping = crafter.craft_ping('8.8.8.8')
            >>> crafter.send_packet(ping)
        """
        try:
            logger.info(f"Sending {count} ICMP packet(s)...")
            send(packet, iface=self.interface, count=count, verbose=self.verbose)
            logger.info("ICMP packet(s) sent successfully")
        except PermissionError:
            logger.error("Permission denied. ICMP packet sending requires root/admin privileges.")
            raise PermissionError("ICMP packet sending requires elevated privileges")
        except Exception as e:
            logger.error(f"Error sending ICMP packet: {e}")
            raise

    def send_and_receive(self, packet: IP, timeout: int = 2) -> Optional[IP]:
        """
        Send an ICMP packet and wait for response.

        Args:
            packet: Packet to send
            timeout: Timeout in seconds

        Returns:
            Response packet or None

        Examples:
            >>> crafter = ICMPCrafter()
            >>> ping = crafter.craft_ping('8.8.8.8')
            >>> response = crafter.send_and_receive(ping)
            >>> if response:
            ...     print(f"Received from {response.src}")
        """
        try:
            logger.info("Sending ICMP packet and waiting for response...")
            response = sr1(packet, iface=self.interface, timeout=timeout, verbose=self.verbose)

            if response:
                logger.info(f"Received response: {response.summary()}")
            else:
                logger.info("No response received")

            return response

        except PermissionError:
            logger.error("Permission denied. ICMP operations require root/admin privileges.")
            raise PermissionError("ICMP operations require elevated privileges")
        except Exception as e:
            logger.error(f"Error in send/receive: {e}")
            raise

    def send_and_receive_multiple(self,
                                   packet: IP,
                                   timeout: int = 2,
                                   count: int = 1) -> List[IP]:
        """
        Send ICMP packet(s) and receive multiple responses.

        Args:
            packet: Packet to send
            timeout: Timeout in seconds
            count: Number of packets to send

        Returns:
            List of response packets
        """
        try:
            logger.info(f"Sending {count} ICMP packet(s) and waiting for responses...")
            answered, unanswered = sr(packet,
                                      iface=self.interface,
                                      timeout=timeout,
                                      verbose=self.verbose,
                                      count=count)

            responses = [rcv for snd, rcv in answered]
            logger.info(f"Received {len(responses)} response(s)")

            return responses

        except PermissionError:
            logger.error("Permission denied. ICMP operations require root/admin privileges.")
            raise PermissionError("ICMP operations require elevated privileges")
        except Exception as e:
            logger.error(f"Error in send/receive multiple: {e}")
            raise

    def perform_ping(self,
                     dst_ip: str,
                     count: int = 4,
                     timeout: int = 2,
                     interval: float = 1.0) -> Dict[str, Any]:
        """
        Perform a complete ping test (multiple echo requests).

        Args:
            dst_ip: Destination IP address
            count: Number of ping packets to send
            timeout: Response timeout per packet
            interval: Interval between packets in seconds

        Returns:
            Dictionary with ping results

        Examples:
            >>> crafter = ICMPCrafter()
            >>> result = crafter.perform_ping('8.8.8.8', count=4)
            >>> print(f"Packet loss: {result['packet_loss']}%")
            >>> print(f"Average RTT: {result['avg_rtt']}ms")
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")

        result = {
            'dst_ip': dst_ip,
            'packets_sent': count,
            'packets_received': 0,
            'packet_loss': 0.0,
            'rtts': [],
            'min_rtt': None,
            'max_rtt': None,
            'avg_rtt': None,
            'responses': []
        }

        logger.info(f"Pinging {dst_ip} with {count} packets...")

        icmp_id = random.randint(1, 65535)

        for seq in range(1, count + 1):
            try:
                ping = self.craft_ping(dst_ip, id=icmp_id, seq=seq)

                start_time = time.time()
                response = self.send_and_receive(ping, timeout)
                end_time = time.time()

                if response and response.haslayer(ICMP):
                    icmp_response = response.getlayer(ICMP)

                    if icmp_response.type == 0:  # Echo Reply
                        rtt = (end_time - start_time) * 1000  # Convert to ms
                        result['packets_received'] += 1
                        result['rtts'].append(rtt)

                        result['responses'].append({
                            'seq': seq,
                            'rtt': rtt,
                            'ttl': response.ttl if hasattr(response, 'ttl') else None
                        })

                        logger.info(f"Reply from {dst_ip}: seq={seq} ttl={response.ttl} time={rtt:.2f}ms")

                # Wait before sending next packet (except for the last one)
                if seq < count:
                    time.sleep(interval)

            except Exception as e:
                logger.debug(f"Error in ping seq={seq}: {e}")

        # Calculate statistics
        result['packet_loss'] = ((count - result['packets_received']) / count) * 100

        if result['rtts']:
            result['min_rtt'] = min(result['rtts'])
            result['max_rtt'] = max(result['rtts'])
            result['avg_rtt'] = sum(result['rtts']) / len(result['rtts'])

        logger.info(f"Ping complete: {result['packets_received']}/{count} packets received, "
                    f"{result['packet_loss']:.1f}% loss")

        if result['rtts']:
            logger.info(f"RTT min/avg/max = {result['min_rtt']:.2f}/"
                        f"{result['avg_rtt']:.2f}/{result['max_rtt']:.2f} ms")

        return result


def craft_icmp_packet(dst_ip: str,
                      type: int = 8,
                      code: int = 0,
                      **kwargs) -> IP:
    """
    Quick helper function to craft an ICMP packet.

    Args:
        dst_ip: Destination IP address
        type: ICMP type (default: 8 for Echo Request)
        code: ICMP code (default: 0)
        **kwargs: Additional ICMP layer arguments

    Returns:
        Crafted IP/ICMP packet

    Examples:
        >>> ping = craft_icmp_packet('8.8.8.8')
        >>> timestamp = craft_icmp_packet('8.8.8.8', type=13, id=1234, seq=1)
    """
    crafter = ICMPCrafter()
    if type == 8 and 'id' in kwargs and 'seq' in kwargs:
        return crafter.craft_ping(dst_ip, kwargs.get('id'), kwargs.get('seq'))
    return crafter.craft_custom(dst_ip, type, code, **kwargs)
