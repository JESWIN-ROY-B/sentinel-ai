"""Logging configuration for Sentinel AI."""

import logging
import sys
from pathlib import Path
from typing import Optional
from .config import config


def setup_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """Set up a logger with the specified name and level."""
    logger = logging.getLogger(name)
    
    if level is None:
        level = config.env.get('log_level', 'INFO')
    
    logger.setLevel(getattr(logging, level.upper()))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    logs_dir = config.get_path('logs_dir')
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.FileHandler(
        logs_dir / 'sentinel_ai.log',
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get an existing logger or create a new one."""
    return logging.getLogger(name)


# Security logger for sensitive events
def get_security_logger() -> logging.Logger:
    """Get a dedicated security logger."""
    logger = logging.getLogger('sentinel_ai.security')
    logger.setLevel(logging.WARNING)
    
    if not logger.handlers:
        logs_dir = config.get_path('logs_dir')
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        security_handler = logging.FileHandler(
            logs_dir / 'security.log',
            encoding='utf-8'
        )
        security_handler.setLevel(logging.WARNING)
        security_formatter = logging.Formatter(
            '%(asctime)s - [SECURITY] - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        security_handler.setFormatter(security_formatter)
        logger.addHandler(security_handler)
    
    return logger


def log_security_event(event_type: str, details: str, level: str = 'WARNING'):
    """Log a security event."""
    security_logger = get_security_logger()
    log_level = getattr(logging, level.upper(), logging.WARNING)
    security_logger.log(log_level, f"{event_type}: {details}")
