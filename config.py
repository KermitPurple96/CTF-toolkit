"""
Configuration management for CTF-toolkit.

This module provides centralized configuration with support for
environment variables and configuration files.
"""

import os
from typing import Dict, Any


class Config:
    """Base configuration class with default values."""

    # Flask configuration
    FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.environ.get('FLASK_PORT', '5000'))
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

    # Security configuration
    USE_HTTPS = os.environ.get('USE_HTTPS', 'False').lower() in ('true', '1', 'yes')
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())

    # File size limits
    MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB
    MAX_CLIPBOARD_SIZE = int(os.environ.get('MAX_CLIPBOARD_SIZE', 10 * 1024 * 1024))  # 10MB

    # Directories
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOLS_FOLDER = os.path.join(BASE_DIR, os.environ.get('TOOLS_FOLDER', 'tools'))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, os.environ.get('UPLOAD_FOLDER', 'uploads'))
    DOWNLOAD_FOLDER = os.path.join(BASE_DIR, os.environ.get('DOWNLOAD_FOLDER', 'downloads'))
    LOG_DIR = os.path.join(BASE_DIR, os.environ.get('LOG_DIR', 'logs'))

    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_TO_FILE = os.environ.get('LOG_TO_FILE', 'True').lower() in ('true', '1', 'yes')
    LOG_TO_CONSOLE = os.environ.get('LOG_TO_CONSOLE', 'True').lower() in ('true', '1', 'yes')
    LOG_MAX_BYTES = int(os.environ.get('LOG_MAX_BYTES', 10 * 1024 * 1024))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get('LOG_BACKUP_COUNT', 5))

    # Listener configuration
    MIN_PORT = int(os.environ.get('MIN_PORT', 1024))
    MAX_PORT = int(os.environ.get('MAX_PORT', 65535))

    # Clipboard configuration
    NUM_CLIPBOARDS = int(os.environ.get('NUM_CLIPBOARDS', 3))

    @classmethod
    def init_app(cls, app: Any = None) -> None:
        """
        Initialize application with configuration.

        Args:
            app: Flask application instance (optional)
        """
        # Create required directories
        for folder in (cls.TOOLS_FOLDER, cls.UPLOAD_FOLDER, cls.DOWNLOAD_FOLDER, cls.LOG_DIR):
            os.makedirs(folder, exist_ok=True)

        if app:
            # Apply Flask configuration
            app.config['MAX_CONTENT_LENGTH'] = cls.MAX_FILE_SIZE
            app.config['SECRET_KEY'] = cls.SECRET_KEY

    @classmethod
    def get_config_dict(cls) -> Dict[str, Any]:
        """
        Get configuration as a dictionary.

        Returns:
            Dictionary with all configuration values
        """
        return {
            'flask': {
                'host': cls.FLASK_HOST,
                'port': cls.FLASK_PORT,
                'debug': cls.FLASK_DEBUG,
                'use_https': cls.USE_HTTPS,
            },
            'security': {
                'max_file_size': cls.MAX_FILE_SIZE,
                'max_clipboard_size': cls.MAX_CLIPBOARD_SIZE,
                'min_port': cls.MIN_PORT,
                'max_port': cls.MAX_PORT,
            },
            'directories': {
                'base_dir': cls.BASE_DIR,
                'tools': cls.TOOLS_FOLDER,
                'uploads': cls.UPLOAD_FOLDER,
                'downloads': cls.DOWNLOAD_FOLDER,
                'logs': cls.LOG_DIR,
            },
            'logging': {
                'level': cls.LOG_LEVEL,
                'to_file': cls.LOG_TO_FILE,
                'to_console': cls.LOG_TO_CONSOLE,
                'max_bytes': cls.LOG_MAX_BYTES,
                'backup_count': cls.LOG_BACKUP_COUNT,
            },
            'clipboards': {
                'count': cls.NUM_CLIPBOARDS,
            }
        }

    @classmethod
    def print_config(cls) -> None:
        """Print current configuration in a readable format."""
        config = cls.get_config_dict()
        print("\n" + "=" * 50)
        print("CTF-Toolkit Configuration")
        print("=" * 50)

        for category, values in config.items():
            print(f"\n[{category.upper()}]")
            for key, value in values.items():
                # Hide secret key
                if key == 'secret_key':
                    value = '***HIDDEN***'
                print(f"  {key}: {value}")

        print("\n" + "=" * 50 + "\n")


class DevelopmentConfig(Config):
    """Development configuration with debug mode enabled."""
    FLASK_DEBUG = True
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """Production configuration with security hardened."""
    FLASK_DEBUG = False
    USE_HTTPS = True
    LOG_LEVEL = 'INFO'


class TestingConfig(Config):
    """Testing configuration."""
    FLASK_DEBUG = False
    LOG_LEVEL = 'DEBUG'
    LOG_TO_CONSOLE = False


# Configuration selector
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': Config
}


def get_config(config_name: str = 'default') -> type:
    """
    Get configuration class by name.

    Args:
        config_name: Configuration name (development, production, testing, default)

    Returns:
        Configuration class
    """
    return config_by_name.get(config_name, Config)
