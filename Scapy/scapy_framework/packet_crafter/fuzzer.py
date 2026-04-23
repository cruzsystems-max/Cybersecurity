"""
Packet Fuzzing Module for Scapy Framework

This module provides packet fuzzing capabilities for security testing,
protocol testing, and vulnerability research.

WARNING: Use only in authorized testing environments.
"""

from typing import Optional, List, Dict, Any, Callable
from scapy.all import fuzz, send, sr, sr1, conf
import random

from scapy_framework.core.logger import get_logger

logger = get_logger(__name__)


class PacketFuzzer:
    """
    Packet Fuzzer for protocol testing and vulnerability research.

    Provides methods to fuzz packet fields, generate mutations, and perform
    automated fuzzing tests.

    WARNING: Fuzzing can crash systems and services. Use only in controlled
    testing environments with proper authorization.
    """

    def __init__(self,
                 interface: Optional[str] = None,
                 verbose: bool = False):
        """
        Initialize Packet Fuzzer.

        Args:
            interface: Network interface to use
            verbose: Enable verbose output

        Examples:
            >>> fuzzer = PacketFuzzer()
            >>> fuzzer = PacketFuzzer(verbose=True)
        """
        self.interface = interface or conf.iface
        self.verbose = verbose

        if not verbose:
            conf.verb = 0

        logger.warning("PacketFuzzer initialized - use only for authorized testing!")
        logger.info(f"Fuzzer ready (interface={self.interface})")

    def fuzz_packet(self, packet, count: int = 10):
        """
        Generate fuzzed variations of a packet.

        Uses Scapy's built-in fuzzing to randomly modify packet fields.

        Args:
            packet: Base packet to fuzz
            count: Number of fuzzed packets to generate

        Returns:
            List of fuzzed packets

        Examples:
            >>> from scapy.all import IP, TCP
            >>> fuzzer = PacketFuzzer()
            >>> base = IP(dst='192.168.1.1')/TCP(dport=80)
            >>> fuzzed = fuzzer.fuzz_packet(base, count=50)
        """
        logger.info(f"Generating {count} fuzzed variations of packet")

        fuzzed_packets = []
        for i in range(count):
            fuzzed = fuzz(packet)
            fuzzed_packets.append(fuzzed)
            logger.debug(f"Generated fuzzed packet {i+1}/{count}")

        logger.info(f"Generated {len(fuzzed_packets)} fuzzed packets")
        return fuzzed_packets

    def fuzz_field(self,
                   packet,
                   layer_name: str,
                   field_name: str,
                   values: Optional[List[Any]] = None,
                   count: int = 10):
        """
        Fuzz a specific field with custom or random values.

        Args:
            packet: Base packet
            layer_name: Layer name (e.g., 'IP', 'TCP', 'UDP')
            field_name: Field name to fuzz (e.g., 'ttl', 'flags', 'dport')
            values: Optional list of values to test (random if not specified)
            count: Number of variations if using random values

        Returns:
            List of packets with fuzzed field

        Examples:
            >>> from scapy.all import IP, TCP
            >>> fuzzer = PacketFuzzer()
            >>> base = IP(dst='192.168.1.1')/TCP(dport=80)
            >>> # Fuzz TCP flags with specific values
            >>> fuzzed = fuzzer.fuzz_field(base, 'TCP', 'flags', ['S', 'SA', 'F', 'R'])
            >>> # Fuzz IP TTL with random values
            >>> fuzzed = fuzzer.fuzz_field(base, 'IP', 'ttl', count=20)
        """
        logger.info(f"Fuzzing field {layer_name}.{field_name}")

        fuzzed_packets = []

        if values:
            # Use provided values
            for value in values:
                pkt = packet.copy()
                if pkt.haslayer(layer_name):
                    setattr(pkt[layer_name], field_name, value)
                    fuzzed_packets.append(pkt)
                    logger.debug(f"Set {layer_name}.{field_name} = {value}")
        else:
            # Generate random values
            for i in range(count):
                pkt = packet.copy()
                if pkt.haslayer(layer_name):
                    # Use Scapy's fuzz on just this layer
                    layer = pkt.getlayer(layer_name)
                    fuzzed_layer = fuzz(layer)
                    # Get the fuzzed field value
                    fuzzed_value = getattr(fuzzed_layer, field_name)
                    setattr(pkt[layer_name], field_name, fuzzed_value)
                    fuzzed_packets.append(pkt)
                    logger.debug(f"Fuzzed {layer_name}.{field_name} = {fuzzed_value}")

        logger.info(f"Generated {len(fuzzed_packets)} packets with fuzzed {field_name}")
        return fuzzed_packets

    def fuzz_payload(self,
                     packet,
                     payload_sizes: Optional[List[int]] = None,
                     count: int = 10):
        """
        Fuzz packet payload with various sizes and content.

        Args:
            packet: Base packet
            payload_sizes: List of payload sizes to test (bytes)
            count: Number of random payloads if sizes not specified

        Returns:
            List of packets with fuzzed payloads

        Examples:
            >>> from scapy.all import IP, UDP, Raw
            >>> fuzzer = PacketFuzzer()
            >>> base = IP(dst='192.168.1.1')/UDP(dport=9999)
            >>> # Test specific payload sizes
            >>> fuzzed = fuzzer.fuzz_payload(base, payload_sizes=[0, 1, 100, 1000, 10000])
            >>> # Test random payloads
            >>> fuzzed = fuzzer.fuzz_payload(base, count=50)
        """
        from scapy.all import Raw

        logger.info("Fuzzing packet payload")

        fuzzed_packets = []

        if payload_sizes:
            for size in payload_sizes:
                pkt = packet.copy()
                if size == 0:
                    # Empty payload
                    fuzzed_packets.append(pkt)
                else:
                    # Random payload of specified size
                    payload = bytes([random.randint(0, 255) for _ in range(size)])
                    pkt = pkt / Raw(load=payload)
                    fuzzed_packets.append(pkt)
                logger.debug(f"Created packet with payload size: {size}")
        else:
            # Random payload sizes
            for i in range(count):
                pkt = packet.copy()
                size = random.choice([0, 1, 8, 16, 64, 256, 512, 1024, 4096, 8192])
                if size > 0:
                    payload = bytes([random.randint(0, 255) for _ in range(size)])
                    pkt = pkt / Raw(load=payload)
                fuzzed_packets.append(pkt)
                logger.debug(f"Created packet with random payload size: {size}")

        logger.info(f"Generated {len(fuzzed_packets)} packets with fuzzed payloads")
        return fuzzed_packets

    def send_fuzzed(self,
                    packets: List,
                    delay: float = 0.1) -> None:
        """
        Send fuzzed packets with optional delay.

        Args:
            packets: List of packets to send
            delay: Delay between packets in seconds

        Examples:
            >>> fuzzer = PacketFuzzer()
            >>> fuzzed = fuzzer.fuzz_packet(base_packet, count=10)
            >>> fuzzer.send_fuzzed(fuzzed, delay=0.5)
        """
        import time

        logger.warning(f"Sending {len(packets)} fuzzed packets")

        try:
            for i, pkt in enumerate(packets):
                logger.debug(f"Sending fuzzed packet {i+1}/{len(packets)}")
                send(pkt, iface=self.interface, verbose=self.verbose)

                if delay > 0 and i < len(packets) - 1:
                    time.sleep(delay)

            logger.info(f"Successfully sent {len(packets)} fuzzed packets")

        except PermissionError:
            logger.error("Permission denied. Packet sending requires root/admin privileges.")
            raise PermissionError("Packet sending requires elevated privileges")
        except Exception as e:
            logger.error(f"Error sending fuzzed packets: {e}")
            raise

    def send_and_receive_fuzzed(self,
                                 packets: List,
                                 timeout: int = 2,
                                 callback: Optional[Callable] = None) -> List[Dict]:
        """
        Send fuzzed packets and collect responses.

        Args:
            packets: List of fuzzed packets to send
            timeout: Response timeout per packet
            callback: Optional callback for each response

        Returns:
            List of dictionaries with packet/response pairs

        Examples:
            >>> def on_response(sent, received):
            ...     print(f"Got response: {received.summary()}")
            >>> fuzzer = PacketFuzzer()
            >>> results = fuzzer.send_and_receive_fuzzed(fuzzed_packets,
            ...                                          callback=on_response)
        """
        logger.info(f"Sending {len(packets)} fuzzed packets and collecting responses")

        results = []

        try:
            for i, pkt in enumerate(packets):
                logger.debug(f"Testing packet {i+1}/{len(packets)}")

                response = sr1(pkt, iface=self.interface, timeout=timeout, verbose=0)

                result = {
                    'packet_num': i + 1,
                    'sent': pkt,
                    'received': response,
                    'got_response': response is not None
                }

                results.append(result)

                if response:
                    logger.debug(f"Packet {i+1}: Got response")
                    if callback:
                        callback(pkt, response)
                else:
                    logger.debug(f"Packet {i+1}: No response")

            responded = len([r for r in results if r['got_response']])
            logger.info(f"Fuzzing complete: {responded}/{len(packets)} packets got responses")

        except PermissionError:
            logger.error("Permission denied. Packet operations require root/admin privileges.")
            raise PermissionError("Packet operations require elevated privileges")
        except Exception as e:
            logger.error(f"Error in fuzzing test: {e}")
            raise

        return results

    def smart_fuzz(self,
                   packet,
                   mutations: int = 100,
                   timeout: int = 2) -> Dict[str, Any]:
        """
        Perform smart fuzzing with mutation tracking and response analysis.

        Args:
            packet: Base packet to fuzz
            mutations: Number of mutations to generate
            timeout: Response timeout

        Returns:
            Dictionary with fuzzing results and statistics

        Examples:
            >>> from scapy.all import IP, TCP
            >>> fuzzer = PacketFuzzer()
            >>> base = IP(dst='192.168.1.1')/TCP(dport=80, flags='S')
            >>> results = fuzzer.smart_fuzz(base, mutations=200)
            >>> print(f"Interesting responses: {len(results['interesting'])}")
        """
        logger.warning(f"Starting smart fuzzing with {mutations} mutations")

        result = {
            'mutations_tested': 0,
            'responses_received': 0,
            'no_response': 0,
            'interesting': [],
            'errors': []
        }

        # Generate mutations
        fuzzed_packets = self.fuzz_packet(packet, mutations)

        # Test each mutation
        for i, fuzzed in enumerate(fuzzed_packets):
            try:
                logger.debug(f"Testing mutation {i+1}/{mutations}")

                response = sr1(fuzzed, iface=self.interface, timeout=timeout, verbose=0)

                result['mutations_tested'] += 1

                if response:
                    result['responses_received'] += 1

                    # Check for interesting responses
                    if self._is_interesting_response(response):
                        result['interesting'].append({
                            'mutation_num': i + 1,
                            'sent': fuzzed,
                            'response': response,
                            'reason': self._analyze_response(response)
                        })
                        logger.info(f"Interesting response found at mutation {i+1}")
                else:
                    result['no_response'] += 1

            except Exception as e:
                result['errors'].append({
                    'mutation_num': i + 1,
                    'error': str(e)
                })
                logger.debug(f"Error in mutation {i+1}: {e}")

        logger.info(f"Smart fuzzing complete: {result['mutations_tested']} mutations tested, "
                    f"{result['responses_received']} responses, "
                    f"{len(result['interesting'])} interesting findings")

        return result

    def _is_interesting_response(self, packet) -> bool:
        """
        Check if a response is interesting (errors, unusual responses, etc.).

        Args:
            packet: Response packet

        Returns:
            True if response is interesting
        """
        from scapy.all import ICMP, TCP

        # ICMP error messages are interesting
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            if icmp_type in [3, 4, 5, 11, 12]:  # Error types
                return True

        # Unusual TCP flags
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags not in [0x02, 0x12, 0x14, 0x10, 0x11, 0x18]:  # Common flags
                return True

        return False

    def _analyze_response(self, packet) -> str:
        """
        Analyze a response packet for interesting characteristics.

        Args:
            packet: Response packet

        Returns:
            Analysis string
        """
        from scapy.all import ICMP, TCP, UDP

        reasons = []

        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            reasons.append(f"ICMP Type {icmp_type} Code {icmp_code}")

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            reasons.append(f"TCP Flags: {flags}")

        if not reasons:
            reasons.append("Unusual response")

        return "; ".join(reasons)


def fuzz_packet(packet, count: int = 10):
    """
    Quick helper function to fuzz a packet.

    Args:
        packet: Base packet to fuzz
        count: Number of fuzzed variations to generate

    Returns:
        List of fuzzed packets

    Examples:
        >>> from scapy.all import IP, TCP
        >>> base = IP(dst='192.168.1.1')/TCP(dport=80)
        >>> fuzzed = fuzz_packet(base, count=20)
    """
    fuzzer = PacketFuzzer()
    return fuzzer.fuzz_packet(packet, count)
