"""
Advanced logging system for the API Security Scanner.

This module provides a comprehensive logging system with multiple levels:
INFO, WARN, ERROR, DEBUG, and FATAL.
"""

import json
import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, Optional, Union

# Define log levels
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "FATAL": logging.CRITICAL
}

# Custom JSON formatter
class JsonFormatter(logging.Formatter):
    """Custom formatter to output logs in JSON format."""
    
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add exception info if available
        if record.exc_info:
            log_record["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }
            
        # Add extra fields if available
        if hasattr(record, "extra"):
            log_record.update(record.extra)
            
        return json.dumps(log_record)


# Rich text formatter with colors
class ColoredFormatter(logging.Formatter):
    """Formatter that adds colors to console output."""
    
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",   # Green
        "WARN": "\033[33m",   # Yellow
        "ERROR": "\033[31m",  # Red
        "FATAL": "\033[35m",  # Magenta
        "RESET": "\033[0m"    # Reset
    }
    
    def format(self, record):
        log_level = record.levelname
        color = self.COLORS.get(log_level, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]
        
        formatter = logging.Formatter(
            f"{color}[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s{reset}",
            "%Y-%m-%d %H:%M:%S"
        )
        
        return formatter.format(record)


def setup_logger(config: Dict = None) -> None:
    """
    Set up the logging system based on configuration.
    
    Args:
        config: Logging configuration dictionary
    """
    if config is None:
        config = {}
        
    # Get log level
    log_level_name = config.get("level", "INFO").upper()
    log_level = LOG_LEVELS.get(log_level_name, logging.INFO)
    
    # Get log format
    log_format = config.get("format", "text").lower()
    
    # Get log output path
    log_output = config.get("output", "logs/scanner.log")
    log_dir = os.path.dirname(log_output)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(ColoredFormatter())
    root_logger.addHandler(console_handler)
    
    # Create file handler if output is specified
    if log_output:
        # Use rotating file handler to prevent huge log files
        file_handler = RotatingFileHandler(
            log_output,
            maxBytes=config.get("max_size", 10 * 1024 * 1024),  # Default: 10MB
            backupCount=config.get("backup_count", 5)
        )
        file_handler.setLevel(log_level)
        
        # Set formatter based on format
        if log_format == "json":
            file_handler.setFormatter(JsonFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                "%Y-%m-%d %H:%M:%S"
            ))
            
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Name of the logger
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_with_context(logger: logging.Logger, level: str, message: str, extra: Dict = None) -> None:
    """
    Log a message with additional context.
    
    Args:
        logger: Logger instance
        level: Log level (DEBUG, INFO, WARN, ERROR, FATAL)
        message: Log message
        extra: Additional context to include in the log
    """
    if extra is None:
        extra = {}
        
    level_method = getattr(logger, level.lower(), logger.info)
    level_method(message, extra={"extra": extra})
