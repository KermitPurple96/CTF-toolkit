"""
Security headers middleware for Flask application.

This module provides security headers to protect against common web vulnerabilities
like XSS, clickjacking, MIME sniffing, and more.
"""

from flask import Flask
from typing import Any


def add_security_headers(app: Flask) -> None:
    """
    Add security headers to all Flask responses.

    Args:
        app: Flask application instance
    """

    @app.after_request
    def set_security_headers(response: Any) -> Any:
        """
        Add security headers to response.

        Args:
            response: Flask response object

        Returns:
            Modified response with security headers
        """
        # Prevent XSS attacks
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # Enable XSS protection in browsers
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Strict Transport Security (force HTTPS)
        # Only uncomment if using HTTPS
        # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions Policy (formerly Feature Policy)
        response.headers['Permissions-Policy'] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=()"
        )

        # Prevent MIME type sniffing
        response.headers['X-Download-Options'] = 'noopen'

        # Prevent DNS prefetching
        response.headers['X-DNS-Prefetch-Control'] = 'off'

        return response


def configure_secure_cookies(app: Flask) -> None:
    """
    Configure secure cookie settings.

    Args:
        app: Flask application instance
    """
    # Set secure cookie defaults
    app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection


def configure_security(app: Flask, use_https: bool = False) -> None:
    """
    Configure all security features for the Flask application.

    Args:
        app: Flask application instance
        use_https: Whether the application is served over HTTPS
    """
    # Add security headers
    add_security_headers(app)

    # Configure secure cookies (only if using HTTPS)
    if use_https:
        configure_secure_cookies(app)
