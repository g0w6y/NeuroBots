"""Logging configuration for the ML Worker."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from config.settings import LoggingConfig


def setup_logging(config: LoggingConfig) -> logging.Logger:
    """Configure and return the root ML worker logger."""
    logger = logging.getLogger("ml_worker")
    logger.setLevel(getattr(logging, config.level.upper(), logging.INFO))

    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, config.level.upper(), logging.INFO))
        formatter = logging.Formatter(config.format, datefmt=config.date_format)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        log_dir = Path(config.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "ml_worker.log")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the ml_worker namespace."""
    return logging.getLogger(f"ml_worker.{name}")
