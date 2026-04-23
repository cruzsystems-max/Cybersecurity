# Scapy Framework

A comprehensive Python framework for network security testing, penetration testing, and network analysis built on top of Scapy.

## Features

- **Network Scanning**
  - ARP scanning for host discovery
  - TCP port scanning (SYN scan)
  - Host discovery tools

- **Packet Analysis**
  - Real-time packet sniffing
  - Protocol analysis (TCP, UDP, DNS, etc.)
  - PCAP file export

- **Security Testing**
  - ARP spoofing detection
  - ARP spoofing attacks (educational/authorized use only)
  - Custom packet crafting

- **CLI Interface**
  - Easy-to-use command-line interface
  - Rich terminal output with tables and colors
  - Multiple export formats

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrator/root privileges (required for packet manipulation)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install Framework

```bash
pip install -e .
```

## Usage

### Command Line Interface

**ARP Scan:**
```bash
# Scan local network
scapy-framework arp-scan 192.168.1.0/24

# Scan with custom interface
scapy-framework arp-scan 192.168.1.0/24 -i eth0

# Export results
scapy-framework arp-scan 192.168.1.0/24 -o results.json
```

**TCP Port Scan:**
```bash
# Scan common ports
scapy-framework tcp-scan 192.168.1.1 -p 1-1000

# Scan specific ports
scapy-framework tcp-scan 192.168.1.1 -p 80,443,8080,3306
```

**Packet Sniffing:**
```bash
# Capture 100 packets
scapy-framework sniff -c 100

# Capture HTTP traffic
scapy-framework sniff -f "tcp port 80" -c 50

# Save to PCAP file
scapy-framework sniff -c 200 -o capture.pcap
```

### Python API

**ARP Scanning:**
```python
from scapy_framework.scanner.arp_scanner import ARPScanner

scanner = ARPScanner()
results = scanner.scan('192.168.1.0/24')

for host in results:
    print(f"{host['ip']} - {host['mac']}")
```

**Packet Sniffing:**
```python
from scapy_framework.analyzer.sniffer import PacketSniffer

def packet_callback(packet):
    print(packet.summary())

sniffer = PacketSniffer(filter="tcp port 80")
sniffer.add_callback(packet_callback)
sniffer.start(count=100)
```

**TCP Packet Crafting:**
```python
from scapy_framework.packet_crafter.tcp_crafter import TCPCrafter

crafter = TCPCrafter()
syn_packet = crafter.craft_syn('192.168.1.1', 80)
response = crafter.send_and_receive(syn_packet)
```

**ARP Spoofing Detection:**
```python
from scapy_framework.defense.arp_detector import ARPDetector

def alert_callback(alert):
    print(f"ALERT: {alert}")

detector = ARPDetector(alert_callback=alert_callback)
detector.start_monitoring()
```

## Project Structure

```
scapy_framework/
├── analyzer/          # Packet analysis tools
│   └── sniffer.py     # Packet sniffer
├── attacks/           # Attack modules (educational)
│   └── arp_spoofing.py
├── core/              # Core functionality
│   ├── logger.py      # Logging system
│   └── config_loader.py
├── defense/           # Defense/detection tools
│   └── arp_detector.py
├── packet_crafter/    # Packet crafting tools
│   └── tcp_crafter.py
├── scanner/           # Network scanning
│   ├── arp_scanner.py
│   ├── tcp_scanner.py
│   └── host_discovery.py
└── utils/             # Utility functions
    ├── network_utils.py
    ├── packet_utils.py
    └── validators.py

cli/                   # Command-line interface
├── main.py           # Main CLI entry point

config/               # Configuration files
docs/                 # Documentation
examples/             # Example scripts
tests/                # Unit tests
```

## Ethical Use Warning

**IMPORTANT:** This framework contains powerful network testing tools that can be used for both defensive and offensive security purposes.

### Legal and Ethical Guidelines:

1. **Only use on networks you own or have explicit written permission to test**
2. **Unauthorized network scanning/attacking is illegal in most jurisdictions**
3. **ARP spoofing and MITM attacks are serious crimes when unauthorized**
4. **Always obtain proper authorization before conducting security tests**
5. **Use for educational purposes on isolated lab environments**

### The authors assume NO responsibility for misuse of this framework.

## Requirements

- scapy >= 2.5.0
- typer >= 0.9.0
- rich >= 13.0.0
- pyyaml >= 6.0
- netifaces >= 0.11.0

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Coverage

```bash
pytest --cov=scapy_framework tests/
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Author

Cristian - Cybersecurity Specialization Project

## Acknowledgments

- Built on top of the excellent [Scapy](https://scapy.net/) library
- Inspired by various network security tools and frameworks

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Remember: With great power comes great responsibility. Use ethically!**
