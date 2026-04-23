"""
Core module for Scapy Framework

This module provides core functionality including configuration loading
and logging setup.
"""

from .config_loader import ConfigLoader
from .logger import setup_logger, get_logger

__all__ = ['ConfigLoader', 'setup_logger', 'get_logger']
