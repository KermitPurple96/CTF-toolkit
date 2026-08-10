"""
Custom exception classes for CTF-toolkit.

This module provides a hierarchy of custom exceptions for better error
handling and clearer error messages throughout the application.
"""


class CTFToolkitError(Exception):
    """Base exception class for all CTF-toolkit errors."""
    pass


# Listener and connection errors
class ListenerError(CTFToolkitError):
    """Base exception for listener-related errors."""
    pass


class ConnectionError(ListenerError):
    """Raised when connection to remote shell fails."""
    pass


class ListenerStartError(ListenerError):
    """Raised when listener fails to start."""
    pass


class ListenerStopError(ListenerError):
    """Raised when listener fails to stop cleanly."""
    pass


# File transfer errors
class FileTransferError(CTFToolkitError):
    """Base exception for file transfer errors."""
    pass


class FileUploadError(FileTransferError):
    """Raised when file upload fails."""
    pass


class FileDownloadError(FileTransferError):
    """Raised when file download fails."""
    pass


class FileIntegrityError(FileTransferError):
    """Raised when MD5 hash verification fails."""
    pass


# Security errors
class SecurityError(CTFToolkitError):
    """Base exception for security-related errors."""
    pass


class PathTraversalError(SecurityError):
    """Raised when path traversal attack is detected."""
    pass


class InvalidInputError(SecurityError):
    """Raised when invalid or malicious input is detected."""
    pass


class FileSizeLimitError(SecurityError):
    """Raised when file size exceeds allowed limit."""
    pass


# Command execution errors
class CommandExecutionError(CTFToolkitError):
    """Raised when remote command execution fails."""
    pass


class TimeoutError(CTFToolkitError):
    """Raised when an operation times out."""
    pass


# OS detection errors
class OSDetectionError(CTFToolkitError):
    """Raised when remote OS detection fails."""
    pass
