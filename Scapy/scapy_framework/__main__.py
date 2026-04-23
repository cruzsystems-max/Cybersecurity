\"\"\"
Entry point for running scapy_framework as a module.

Usage: python -m scapy_framework [command] [options]
\"\"\"

from cli.main import app

if __name__ == "__main__":
    app()
