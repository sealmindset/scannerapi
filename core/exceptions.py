"""
Custom exceptions for the API Security Scanner.

This module defines custom exceptions used throughout the scanner.
"""

class ScannerError(Exception):
    """Base exception for all scanner errors."""
    pass


class ScannerConfigError(ScannerError):
    """Exception raised for configuration errors."""
    pass


class ScannerExecutionError(ScannerError):
    """Exception raised for scanner execution errors."""
    pass


class ScannerConnectionError(ScannerError):
    """Exception raised for connection errors."""
    pass


class ScannerAuthenticationError(ScannerError):
    """Exception raised for authentication errors."""
    pass


class ScannerTimeoutError(ScannerError):
    """Exception raised for timeout errors."""
    pass


class ScannerRateLimitError(ScannerError):
    """Exception raised for rate limit errors."""
    pass


class ScannerValidationError(ScannerError):
    """Exception raised for validation errors."""
    pass


class ScannerDependencyError(ScannerError):
    """Exception raised for missing dependencies."""
    pass
