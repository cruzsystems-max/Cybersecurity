"""
UDP Packet Crafting Module for Scapy Framework

This module provides comprehensive UDP packet crafting capabilities for network
security testing and educational purposes.
"""

from typing import Optional, List, Dict, Any
from scapy.all import IP, UDP, send, sr1, sr, conf, Raw, DNS, DNSQR
import random

from scapy_framework.core.logger import get_logger
from scapy_framework.utils.validators import is_valid_ip, is_valid_port

logger = get_logger(__name__)


class UDPCrafter:
    """
    UDP Packet Crafter for custom UDP packet generation.

    Provides methods to craft various UDP packets for network testing including
    DNS queries, custom payloads, and UDP-based protocol testing.
    """

    def __init__(self,
                 src_ip: Optional[str] = None,
                 interface: Optional[str] = None,
                 verbose: bool = False):
        """
        Initialize UDP Crafter.

        Args:
            src_ip: Source IP address (optional, defaults to interface IP)
            interface: Network interface to use
            verbose: Enable verbose output

        Examples:
            >>> crafter = UDPCrafter()
            >>> crafter = UDPCrafter(src_ip='192.168.1.100', verbose=True)
        """
        self.src_ip = src_ip
        self.interface = interface or conf.iface
        self.verbose = verbose

        if not verbose:
            conf.verb = 0

        logger.info(f"UDP Crafter initialized (interface={self.interface})")

    def craft_udp(self,
                  dst_ip: str,
                  dst_port: int,
                  src_port: Optional[int] = None,
                  payload: Optional[str] = None) -> IP:
        """
        Craft a basic UDP packet.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port (random if not specified)
            payload: Optional payload data

        Returns:
            Crafted IP/UDP packet

        Raises:
            ValueError: If IP or port is invalid

        Examples:
            >>> crafter = UDPCrafter()
            >>> packet = crafter.craft_udp('192.168.1.1', 53, payload='test')
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")
        if not is_valid_port(dst_port):
            raise ValueError(f"Invalid destination port: {dst_port}")

        if src_port is None:
            src_port = random.randint(1024, 65535)

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        udp_layer = UDP(sport=src_port, dport=dst_port)
        packet = ip_layer / udp_layer

        if payload:
            packet = packet / Raw(load=payload)

        logger.debug(f"Crafted UDP packet: {dst_ip}:{dst_port} (sport={src_port})")
        return packet

    def craft_dns_query(self,
                        dns_server: str,
                        domain: str,
                        qtype: str = 'A',
                        src_port: Optional[int] = None) -> IP:
        """
        Craft a DNS query packet.

        Args:
            dns_server: DNS server IP address
            domain: Domain name to query
            qtype: Query type ('A', 'AAAA', 'MX', 'NS', etc.)
            src_port: Source port (random if not specified)

        Returns:
            Crafted IP/UDP/DNS packet

        Examples:
            >>> crafter = UDPCrafter()
            >>> query = crafter.craft_dns_query('8.8.8.8', 'example.com')
            >>> response = crafter.send_and_receive(query)
        """
        if not is_valid_ip(dns_server):
            raise ValueError(f"Invalid DNS server IP: {dns_server}")

        if src_port is None:
            src_port = random.randint(1024, 65535)

        ip_layer = IP(dst=dns_server)
        if self.src_ip:
            ip_layer.src = self.src_ip

        udp_layer = UDP(sport=src_port, dport=53)
        dns_layer = DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))

        packet = ip_layer / udp_layer / dns_layer

        logger.debug(f"Crafted DNS query: {domain} ({qtype}) -> {dns_server}")
        return packet

    def craft_custom(self,
                     dst_ip: str,
                     dst_port: int,
                     src_port: Optional[int] = None,
                     payload: Optional[bytes] = None,
                     length: Optional[int] = None,
                     checksum: Optional[int] = None) -> IP:
        """
        Craft a custom UDP packet with full control over fields.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            src_port: Source port (random if not specified)
            payload: Raw payload bytes
            length: UDP length field (calculated if not specified)
            checksum: UDP checksum (calculated if not specified)

        Returns:
            Crafted IP/UDP packet

        Examples:
            >>> crafter = UDPCrafter()
            >>> packet = crafter.craft_custom('192.168.1.1', 9999,
            ...                               payload=b'\\x00\\x01\\x02\\x03')
        """
        if not is_valid_ip(dst_ip):
            raise ValueError(f"Invalid destination IP: {dst_ip}")
        if not is_valid_port(dst_port):
            raise ValueError(f"Invalid destination port: {dst_port}")

        if src_port is None:
            src_port = random.randint(1024, 65535)

        ip_layer = IP(dst=dst_ip)
        if self.src_ip:
            ip_layer.src = self.src_ip

        udp_kwargs = {
            'sport': src_port,
            'dport': dst_port
        }

        if length is not None:
            udp_kwargs['len'] = length
        if checksum is not None:
            udp_kwargs['chksum'] = checksum

        udp_layer = UDP(**udp_kwargs)
        packet = ip_layer / udp_layer

        if payload:
            packet = packet / Raw(load=payload)

        logger.debug(f"Crafted custom UDP packet: {dst_ip}:{dst_port}")
        return packet

    def craft_udp_flood(self,
                        dst_ip: str,
                        dst_port: int,
                        count: int = 10,
                        payload_size: int = 64) -> List[IP]:
        """
        Craft multiple UDP packets for flood testing.

        WARNING: Use only in authorized testing environments.

        Args:
            dst_ip: Destination IP address
            dst_port: Destination port
            count: Number of packets to craft
            payload_size: Size of random payload in bytes

        Returns:
            List of crafted UDP packets

        Examples:
            >>> crafter = UDPCrafter()
            >>> packets = crafter.craft_udp_flood('192.168.1.100', 9999, count=50)
        """
        logger.warning("Creating UDP flood packets - use only for authorized testing!")

        packets = []
        for _ in range(count):
            src_port = random.randint(1024, 65535)
            payload = bytes([random.randint(0, 255) for _ in range(payload_size)])

            packet = self.craft_custom(dst_ip, dst_port, src_port, payload)
            packets.append(packet)

        logger.info(f"Crafted {count} UDP flood packets")
        return packets

    def send_packet(self, packet: IP, count: int = 1) -> None:
        """
        Send a crafted UDP packet.

        Args:
            packet: Packet to send
            count: Number of times to send

        Examples:
            >>> crafter = UDPCrafter()
            >>> udp = crafter.craft_udp('192.168.1.1', 9999)
            >>> crafter.send_packet(udp)
        """
        try:
            logger.info(f"Sending {count} UDP packet(s)...")
            send(packet, iface=self.interface, count=count, verbose=self.verbose)
            logger.info("UDP packet(s) sent successfully")
        except PermissionError:
            logger.error("Permission denied. Packet sending requires root/admin privileges.")
            raise PermissionError("Packet sending requires elevated privileges")
        except Exception as e:
            logger.error(f"Error sending UDP packet: {e}")
            raise

    def send_and_receive(self, packet: IP, timeout: int = 2) -> Optional[IP]:
        """
        Send a UDP packet and wait for response.

        Args:
            packet: Packet to send
            timeout: Timeout in seconds

        Returns:
            Response packet or None

        Examples:
            >>> crafter = UDPCrafter()
            >>> dns_query = crafter.craft_dns_query('8.8.8.8', 'example.com')
            >>> response = crafter.send_and_receive(dns_query)
            >>> if response and response.haslayer(DNS):
            ...     print(response[DNS].an.rdata)
        """
        try:
            logger.info("Sending UDP packet and waiting for response...")
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
        Send UDP packet(s) and receive multiple responses.

        Args:
            packet: Packet to send
            timeout: Timeout in seconds
            count: Number of packets to send

        Returns:
            List of response packets
        """
        try:
            logger.info(f"Sending {count} UDP packet(s) and waiting for responses...")
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

    def perform_dns_lookup(self,
                           dns_server: str,
                           domain: str,
                           qtype: str = 'A',
                           timeout: int = 2) -> Dict[str, Any]:
        """
        Perform a complete DNS lookup.

        Args:
            dns_server: DNS server IP address
            domain: Domain name to query
            qtype: Query type ('A', 'AAAA', 'MX', 'NS', etc.)
            timeout: Response timeout

        Returns:
            Dictionary with DNS lookup results

        Examples:
            >>> crafter = UDPCrafter()
            >>> result = crafter.perform_dns_lookup('8.8.8.8', 'example.com')
            >>> if result['success']:
            ...     print(f"IP: {result['answers']}")
        """
        result = {
            'success': False,
            'domain': domain,
            'qtype': qtype,
            'dns_server': dns_server,
            'answers': []
        }

        try:
            logger.info(f"Performing DNS lookup for {domain} ({qtype}) via {dns_server}")

            query = self.craft_dns_query(dns_server, domain, qtype)
            response = self.send_and_receive(query, timeout)

            if not response or not response.haslayer(DNS):
                result['error'] = 'No DNS response received'
                return result

            dns_response = response.getlayer(DNS)

            if dns_response.ancount > 0:
                for i in range(dns_response.ancount):
                    answer = dns_response.an[i]
                    result['answers'].append({
                        'name': answer.rrname.decode() if hasattr(answer.rrname, 'decode') else str(answer.rrname),
                        'type': answer.type,
                        'data': answer.rdata if isinstance(answer.rdata, str) else str(answer.rdata)
                    })

                result['success'] = True
                logger.info(f"DNS lookup successful: {len(result['answers'])} answer(s)")
            else:
                result['error'] = 'No answers in DNS response'
                logger.info("DNS response received but no answers")

        except Exception as e:
            logger.error(f"DNS lookup failed: {e}")
            result['error'] = str(e)

        return result


def craft_udp_packet(dst_ip: str,
                     dst_port: int,
                     src_port: Optional[int] = None,
                     payload: Optional[str] = None) -> IP:
    """
    Quick helper function to craft a UDP packet.

    Args:
        dst_ip: Destination IP address
        dst_port: Destination port
        src_port: Source port (random if not specified)
        payload: Optional payload data

    Returns:
        Crafted IP/UDP packet

    Examples:
        >>> udp = craft_udp_packet('192.168.1.1', 9999)
        >>> dns = craft_udp_packet('8.8.8.8', 53, payload='dns_query')
    """
    crafter = UDPCrafter()
    return crafter.craft_udp(dst_ip, dst_port, src_port, payload)
