"""
Logging System for Scapy Framework

This module provides a structured logging system with file rotation,
multiple handlers, and customizable formats.
"""

import logging
import logging.config
import logging.handlers
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """
    Colored log formatter for console output.

    Adds color codes to log levels for better readability.
    """

    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        # Add color to level name
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"

        # Format the record
        result = super().format(record)

        # Reset levelname for other formatters
        record.levelname = levelname

        return result


class FrameworkLogger:
    """
    Centralized logging manager for the framework.

    Handles setup of file and console handlers with rotation.
    """

    def __init__(self, name: str = "scapy_framework", config: Optional[Dict[str, Any]] = None):
        """
        Initialize the logger.

        Args:
            name: Logger name
            config: Optional configuration dictionary
        """
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(name)
        self._setup_logger()

    def _setup_logger(self) -> None:
        """Setup logger with handlers and formatters."""
        # Clear existing handlers
        self.logger.handlers.clear()

        # Set log level
        log_level = self.config.get('level', 'INFO')
        self.logger.setLevel(getattr(logging, log_level.upper()))

        # Setup file handler
        if self.config.get('file'):
            self._setup_file_handler()

        # Setup console handler
        if self.config.get('console_enabled', True):
            self._setup_console_handler()

    def _setup_file_handler(self) -> None:
        """Setup rotating file handler."""
        log_file = self.config.get('file', 'logs/scapy_framework.log')
        log_path = Path(log_file)

        # Create logs directory if it doesn't exist
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Get rotation settings
        max_bytes = self.config.get('max_bytes', 10485760)  # 10 MB
        backup_count = self.config.get('backup_count', 5)

        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )

        # Set format
        log_format = self.config.get('format',
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        date_format = self.config.get('date_format', '%Y-%m-%d %H:%M:%S')

        formatter = logging.Formatter(log_format, datefmt=date_format)
        file_handler.setFormatter(formatter)

        # Set level
        file_handler.setLevel(logging.DEBUG)

        # Add handler
        self.logger.addHandler(file_handler)

    def _setup_console_handler(self) -> None:
        """Setup console handler with colors."""
        console_handler = logging.StreamHandler()

        # Set format with colors
        log_format = self.config.get('format',
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        date_format = self.config.get('date_format', '%Y-%m-%d %H:%M:%S')

        formatter = ColoredFormatter(log_format, datefmt=date_format)
        console_handler.setFormatter(formatter)

        # Set level
        console_level = self.config.get('console_level', 'INFO')
        console_handler.setLevel(getattr(logging, console_level.upper()))

        # Add handler
        self.logger.addHandler(console_handler)

    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        return self.logger


# Global logger instances
_loggers: Dict[str, FrameworkLogger] = {}


def setup_logger(name: str = "scapy_framework", config: Optional[Dict[str, Any]] = None) -> logging.Logger:
    """
    Setup and configure a logger.

    Args:
        name: Logger name
        config: Optional configuration dictionary with logging settings

    Returns:
        Configured logger instance

    Examples:
        >>> logger = setup_logger('scapy_framework.scanner')
        >>> logger.info('Starting ARP scan')
    """
    if name not in _loggers:
        _loggers[name] = FrameworkLogger(name, config)

    return _loggers[name].get_logger()


def get_logger(name: str = "scapy_framework") -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance

    Examples:
        >>> logger = get_logger('scapy_framework.scanner')
        >>> logger.debug('Debug message')
    """
    if name not in _loggers:
        # Try to load config from global config
        try:
            from scapy_framework.core.config_loader import get_config
            config = get_config()
            logging_config = config.get_section('logging')
            return setup_logger(name, logging_config)
        except:
            # Fallback to basic logger
            return setup_logger(name, {'level': 'INFO', 'console_enabled': True})

    return _loggers[name].get_logger()


def setup_from_json_config(config_path: str) -> None:
    """
    Setup logging from JSON configuration file.

    Args:
        config_path: Path to JSON logging configuration file

    Examples:
        >>> setup_from_json_config('config/logging_config.json')
    """
    config_path_obj = Path(config_path)

    if not config_path_obj.exists():
        raise FileNotFoundError(f"Logging config file not found: {config_path}")

    with open(config_path_obj, 'r', encoding='utf-8') as f:
        config = json.load(f)

    # Create logs directory if specified in config
    for handler_name, handler_config in config.get('handlers', {}).items():
        if 'filename' in handler_config:
            log_path = Path(handler_config['filename'])
            log_path.parent.mkdir(parents=True, exist_ok=True)

    # Apply configuration
    logging.config.dictConfig(config)


def log_function_call(logger: logging.Logger):
    """
    Decorator to log function calls.

    Args:
        logger: Logger instance to use

    Examples:
        >>> logger = get_logger('scapy_framework.scanner')
        >>> @log_function_call(logger)
        ... def scan_network(target):
        ...     pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            try:
                result = func(*args, **kwargs)
                logger.debug(f"{func.__name__} completed successfully")
                return result
            except Exception as e:
                logger.error(f"{func.__name__} failed with error: {e}")
                raise
        return wrapper
    return decorator


# Setup default logger
default_logger = get_logger()
