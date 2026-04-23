\"\"\"
Main CLI Entry Point for Scapy Framework
\"\"\"

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional

from scapy_framework.scanner.arp_scanner import ARPScanner
from scapy_framework.scanner.tcp_scanner import TCPScanner
from scapy_framework.analyzer.sniffer import PacketSniffer
from scapy_framework.core.logger import get_logger

app = typer.Typer(help="Scapy Framework - Network Security Testing Tool")
console = Console()
logger = get_logger(__name__)


@app.command()
def arp_scan(
    target: str = typer.Argument(..., help="Target network (CIDR notation)"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface"),
    timeout: float = typer.Option(1.0, "--timeout", "-t", help="Timeout in seconds"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file")
):
    \"\"\"Perform ARP scan to discover hosts.\"\"\"
    console.print(f"[bold blue]Starting ARP scan on {target}...[/bold blue]")
    
    scanner = ARPScanner(interface=interface, timeout=timeout)
    results = scanner.scan(target)
    
    table = Table(title=f"ARP Scan Results - {target}")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="green")
    
    for host in results:
        table.add_row(host['ip'], host['mac'])
    
    console.print(table)
    console.print(f"[bold green]Found {len(results)} hosts[/bold green]")
    
    if output:
        scanner.export_results(output, output.split('.')[-1])
        console.print(f"[green]Results saved to {output}[/green]")


@app.command()
def tcp_scan(
    target: str = typer.Argument(..., help="Target IP address"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Port range"),
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Timeout")
):
    \"\"\"Perform TCP port scan.\"\"\"
    console.print(f"[bold blue]Scanning {target}...[/bold blue]")
    
    scanner = TCPScanner(interface=interface, timeout=timeout)
    
    if '-' in ports:
        start, end = map(int, ports.split('-'))
        port_list = list(range(start, end + 1))
    else:
        port_list = [int(p) for p in ports.split(',')]
    
    results = scanner.scan(target, port_list)
    
    table = Table(title=f"TCP Scan Results - {target}")
    table.add_column("Port", style="cyan")
    table.add_column("State", style="green")
    
    for port, state in results.items():
        table.add_row(str(port), state)
    
    console.print(table)
    open_count = len([s for s in results.values() if s == 'open'])
    console.print(f"[bold green]Found {open_count} open ports[/bold green]")


@app.command()
def sniff(
    interface: Optional[str] = typer.Option(None, "--interface", "-i", help="Network interface"),
    filter: Optional[str] = typer.Option(None, "--filter", "-f", help="BPF filter"),
    count: int = typer.Option(100, "--count", "-c", help="Number of packets"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output PCAP file")
):
    \"\"\"Capture network packets.\"\"\"
    console.print(f"[bold blue]Starting packet capture...[/bold blue]")
    if filter:
        console.print(f"[yellow]Filter: {filter}[/yellow]")
    
    sniffer = PacketSniffer(interface=interface, filter=filter)
    packets = sniffer.start(count=count)
    
    console.print(f"[bold green]Captured {len(packets)} packets[/bold green]")
    
    if output:
        sniffer.save_packets(output)
        console.print(f"[green]Packets saved to {output}[/green]")


@app.command()
def version():
    \"\"\"Show version information.\"\"\"
    console.print("[bold blue]Scapy Framework v1.0.0[/bold blue]")
    console.print("Network Security Testing Tool")


if __name__ == "__main__":
    app()
