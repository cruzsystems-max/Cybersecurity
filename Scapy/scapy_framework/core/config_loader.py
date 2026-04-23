"""
Configuration Loader for Scapy Framework

This module handles loading and managing configuration from YAML files.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigLoader:
    """
    Configuration loader that handles YAML configuration files.

    Supports loading default configuration and merging with user overrides.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration loader.

        Args:
            config_path: Optional path to custom configuration file.
                        If not provided, uses default configuration.
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self._load_config()

    def _get_default_config_path(self) -> Path:
        """Get the path to the default configuration file."""
        # Get the package root directory
        package_root = Path(__file__).parent.parent.parent
        default_config = package_root / "config" / "default_config.yaml"
        return default_config

    def _load_config(self) -> None:
        """Load configuration from file."""
        # Load default configuration first
        default_config_path = self._get_default_config_path()

        if default_config_path.exists():
            with open(default_config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
        else:
            # Fallback to minimal default configuration
            self.config = self._get_minimal_config()

        # If custom config path provided, merge it
        if self.config_path:
            custom_config_path = Path(self.config_path)
            if custom_config_path.exists():
                with open(custom_config_path, 'r', encoding='utf-8') as f:
                    custom_config = yaml.safe_load(f) or {}
                    self.config = self._merge_configs(self.config, custom_config)

    def _get_minimal_config(self) -> Dict[str, Any]:
        """Return minimal fallback configuration."""
        return {
            "network": {
                "default_interface": "",
                "timeout": 2,
                "retry": 3,
                "verbose": False
            },
            "logging": {
                "level": "INFO",
                "file": "logs/scapy_framework.log",
                "max_bytes": 10485760,
                "backup_count": 5,
                "console_enabled": True
            },
            "security": {
                "require_confirmation": True,
                "allowed_networks": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
            }
        }

    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge two configuration dictionaries.

        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary

        Returns:
            Merged configuration dictionary
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.

        Args:
            key: Configuration key in dot notation (e.g., 'network.timeout')
            default: Default value if key not found

        Returns:
            Configuration value or default

        Examples:
            >>> config = ConfigLoader()
            >>> timeout = config.get('network.timeout', 2)
            >>> allowed_nets = config.get('security.allowed_networks', [])
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.

        Args:
            key: Configuration key in dot notation
            value: Value to set

        Examples:
            >>> config = ConfigLoader()
            >>> config.set('network.timeout', 5)
        """
        keys = key.split('.')
        target = self.config

        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]

        target[keys[-1]] = value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get an entire configuration section.

        Args:
            section: Section name (e.g., 'network', 'scanner')

        Returns:
            Configuration section as dictionary
        """
        return self.config.get(section, {})

    def reload(self) -> None:
        """Reload configuration from file."""
        self._load_config()

    def save(self, path: Optional[str] = None) -> None:
        """
        Save current configuration to file.

        Args:
            path: Path to save configuration. If not provided, uses config_path.
        """
        save_path = path or self.config_path
        if not save_path:
            raise ValueError("No path specified for saving configuration")

        save_path_obj = Path(save_path)
        save_path_obj.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path_obj, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access to configuration."""
        return self.get(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Allow dictionary-style setting of configuration."""
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        """Check if a configuration key exists."""
        return self.get(key) is not None

    def __repr__(self) -> str:
        """String representation of configuration."""
        return f"ConfigLoader(config_path={self.config_path})"


# Global configuration instance
_global_config: Optional[ConfigLoader] = None


def get_config(config_path: Optional[str] = None) -> ConfigLoader:
    """
    Get the global configuration instance.

    Args:
        config_path: Optional path to configuration file

    Returns:
        Global ConfigLoader instance
    """
    global _global_config

    if _global_config is None:
        _global_config = ConfigLoader(config_path)

    return _global_config


def reset_config() -> None:
    """Reset the global configuration instance."""
    global _global_config
    _global_config = None
