"""
Input validation helpers for CTF-toolkit.

This module provides reusable validation functions to ensure
input data meets security and format requirements.
"""

import os
import re
from typing import Tuple, Optional
from exceptions import PathTraversalError, InvalidInputError


def validate_filename(filename: str) -> str:
    """
    Validate that a filename is safe and doesn't contain path traversal attempts.

    Args:
        filename: The filename to validate

    Returns:
        The validated filename

    Raises:
        InvalidInputError: If filename is empty or contains null bytes
        PathTraversalError: If filename contains path traversal patterns
    """
    if not filename:
        raise InvalidInputError("Filename cannot be empty")

    # Check for null bytes
    if '\0' in filename:
        raise InvalidInputError("Filename contains null bytes")

    # Check for path traversal
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        raise PathTraversalError(f"Path traversal attempt detected: {filename}")

    # Check for absolute paths on Windows
    if len(filename) > 1 and filename[1] == ':':
        raise PathTraversalError(f"Absolute path not allowed: {filename}")

    return filename


def validate_path_in_directory(filepath: str, allowed_directory: str) -> Tuple[str, str]:
    """
    Validate that a filepath is within an allowed directory.

    Args:
        filepath: The file path to validate
        allowed_directory: The directory that should contain the file

    Returns:
        Tuple of (absolute_filepath, absolute_directory)

    Raises:
        PathTraversalError: If path is outside allowed directory
    """
    abs_directory = os.path.abspath(allowed_directory) + os.sep
    abs_filepath = os.path.abspath(filepath)

    if not abs_filepath.startswith(abs_directory):
        raise PathTraversalError(
            f"Path {filepath} is outside allowed directory {allowed_directory}"
        )

    return abs_filepath, abs_directory


def validate_port(port: int) -> int:
    """
    Validate that a port number is valid and not privileged.

    Args:
        port: Port number to validate

    Returns:
        The validated port number

    Raises:
        InvalidInputError: If port is out of valid range
    """
    if port < 1024 or port > 65535:
        raise InvalidInputError(
            f"Invalid port {port}: must be between 1024-65535"
        )

    return port


def validate_clipboard_index(index: int, max_index: int) -> int:
    """
    Validate that a clipboard index is within valid range.

    Args:
        index: The clipboard index to validate
        max_index: Maximum allowed index (exclusive)

    Returns:
        The validated index

    Raises:
        InvalidInputError: If index is out of range
    """
    if index < 0 or index >= max_index:
        raise InvalidInputError(
            f"Invalid clipboard index {index}: must be between 0-{max_index-1}"
        )

    return index


def validate_content_size(content: str, max_size: int, content_type: str = "content") -> str:
    """
    Validate that content size doesn't exceed maximum allowed.

    Args:
        content: The content to validate
        max_size: Maximum allowed size in bytes
        content_type: Type of content for error message

    Returns:
        The validated content

    Raises:
        InvalidInputError: If content exceeds max size
    """
    content_size = len(content.encode('utf-8'))

    if content_size > max_size:
        raise InvalidInputError(
            f"{content_type.capitalize()} size {content_size} exceeds limit {max_size}"
        )

    return content


def validate_command(command: str) -> str:
    """
    Basic validation for shell commands.

    Args:
        command: Command string to validate

    Returns:
        The validated command

    Raises:
        InvalidInputError: If command is empty or too long
    """
    if not command or not command.strip():
        raise InvalidInputError("Command cannot be empty")

    # Prevent extremely long commands (potential DoS)
    max_command_length = 10000
    if len(command) > max_command_length:
        raise InvalidInputError(
            f"Command too long: {len(command)} > {max_command_length}"
        )

    return command.strip()


def sanitize_log_message(message: str) -> str:
    """
    Sanitize a message for logging to prevent log injection.

    Args:
        message: The message to sanitize

    Returns:
        Sanitized message safe for logging
    """
    # Remove newlines and carriage returns to prevent log injection
    sanitized = message.replace('\n', '\\n').replace('\r', '\\r')

    # Limit message length
    max_length = 1000
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... (truncated)"

    return sanitized
