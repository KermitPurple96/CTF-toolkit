"""
Rate limiting middleware for Flask application.

This module provides IP-based rate limiting to prevent abuse
and DoS attacks without requiring external dependencies.
"""

import time
from collections import defaultdict
from typing import Dict, Tuple, Optional
from functools import wraps
from flask import request, jsonify
from logging_config import get_logger

logger = get_logger('rate_limiter')


class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window algorithm.

    Attributes:
        requests: Dictionary tracking requests per IP
        window_size: Time window in seconds
        max_requests: Maximum requests allowed per window
    """

    def __init__(self, window_size: int = 60, max_requests: int = 100):
        """
        Initialize rate limiter.

        Args:
            window_size: Time window in seconds (default: 60)
            max_requests: Maximum requests per window (default: 100)
        """
        self.requests: Dict[str, list] = defaultdict(list)
        self.window_size = window_size
        self.max_requests = max_requests
        self._cleanup_interval = 300  # Clean up every 5 minutes
        self._last_cleanup = time.time()

    def _cleanup(self) -> None:
        """Remove old entries to prevent memory growth."""
        current_time = time.time()

        if current_time - self._last_cleanup < self._cleanup_interval:
            return

        cutoff_time = current_time - self.window_size

        # Remove IPs with no recent requests
        ips_to_remove = []
        for ip, timestamps in self.requests.items():
            # Remove old timestamps
            self.requests[ip] = [ts for ts in timestamps if ts > cutoff_time]

            # Mark IP for removal if no recent requests
            if not self.requests[ip]:
                ips_to_remove.append(ip)

        for ip in ips_to_remove:
            del self.requests[ip]

        self._last_cleanup = current_time

        if ips_to_remove:
            logger.debug(f"Cleaned up {len(ips_to_remove)} inactive IPs from rate limiter")

    def is_allowed(self, ip: str) -> Tuple[bool, Optional[int]]:
        """
        Check if request from IP is allowed.

        Args:
            ip: Client IP address

        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        self._cleanup()

        current_time = time.time()
        cutoff_time = current_time - self.window_size

        # Get recent requests from this IP
        recent_requests = [ts for ts in self.requests[ip] if ts > cutoff_time]

        if len(recent_requests) >= self.max_requests:
            # Calculate when the oldest request will expire
            oldest_request = min(recent_requests)
            retry_after = int(oldest_request + self.window_size - current_time) + 1

            logger.warning(
                f"Rate limit exceeded for {ip}: "
                f"{len(recent_requests)}/{self.max_requests} requests in {self.window_size}s"
            )

            return False, retry_after

        # Add current request
        recent_requests.append(current_time)
        self.requests[ip] = recent_requests

        return True, None

    def reset(self, ip: Optional[str] = None) -> None:
        """
        Reset rate limit for an IP or all IPs.

        Args:
            ip: IP address to reset, or None to reset all
        """
        if ip:
            if ip in self.requests:
                del self.requests[ip]
                logger.info(f"Reset rate limit for {ip}")
        else:
            self.requests.clear()
            logger.info("Reset rate limit for all IPs")


# Global rate limiters for different endpoint categories
default_limiter = RateLimiter(window_size=60, max_requests=100)  # 100 req/min
strict_limiter = RateLimiter(window_size=60, max_requests=20)    # 20 req/min
auth_limiter = RateLimiter(window_size=300, max_requests=5)      # 5 req/5min


def rate_limit(limiter: RateLimiter = default_limiter):
    """
    Decorator to apply rate limiting to Flask routes.

    Args:
        limiter: RateLimiter instance to use

    Returns:
        Decorated function with rate limiting

    Example:
        @app.route('/api/endpoint')
        @rate_limit(strict_limiter)
        def my_endpoint():
            return jsonify({"status": "ok"})
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            ip = request.remote_addr

            # Check if request is allowed
            allowed, retry_after = limiter.is_allowed(ip)

            if not allowed:
                logger.warning(f"Rate limit exceeded for {ip} on {request.path}")
                response = jsonify({
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Please try again in {retry_after} seconds.",
                    "retry_after": retry_after
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                return response

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def get_rate_limit_status(ip: str, limiter: RateLimiter = default_limiter) -> Dict:
    """
    Get current rate limit status for an IP.

    Args:
        ip: IP address to check
        limiter: RateLimiter instance

    Returns:
        Dictionary with rate limit status
    """
    current_time = time.time()
    cutoff_time = current_time - limiter.window_size

    recent_requests = [ts for ts in limiter.requests.get(ip, []) if ts > cutoff_time]

    return {
        "ip": ip,
        "requests_made": len(recent_requests),
        "max_requests": limiter.max_requests,
        "window_size": limiter.window_size,
        "remaining": max(0, limiter.max_requests - len(recent_requests)),
        "reset_at": int(min(recent_requests, default=current_time) + limiter.window_size) if recent_requests else None
    }
