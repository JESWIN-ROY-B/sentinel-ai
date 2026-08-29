"""Path management utilities for Sentinel AI."""

from pathlib import Path
from typing import Union
from .config import config


def get_project_root() -> Path:
    """Get the project root directory."""
    return config.project_root


def get_data_dir() -> Path:
    """Get the data directory."""
    return config.get_path('data_dir')


def get_raw_data_dir() -> Path:
    """Get the raw data directory."""
    return config.get_path('raw_data_dir')


def get_processed_data_dir() -> Path:
    """Get the processed data directory."""
    return config.get_path('processed_data_dir')


def get_sample_data_dir() -> Path:
    """Get the sample data directory."""
    return config.get_path('sample_data_dir')


def get_model_dir() -> Path:
    """Get the models directory."""
    return config.get_path('model_dir')


def get_artifact_dir() -> Path:
    """Get the artifacts directory."""
    return config.get_path('artifact_dir')


def get_metrics_dir() -> Path:
    """Get the metrics directory."""
    return config.get_path('metrics_dir')


def get_figures_dir() -> Path:
    """Get the figures directory."""
    return config.get_path('figures_dir')


def get_logs_dir() -> Path:
    """Get the logs directory."""
    return config.get_path('logs_dir')


def get_config_dir() -> Path:
    """Get the config directory."""
    return config.config_dir


def resolve_path(path: Union[str, Path]) -> Path:
    """Resolve a path relative to project root if not absolute."""
    path = Path(path)
    if not path.is_absolute():
        return get_project_root() / path
    return path


def ensure_dir(path: Union[str, Path]) -> Path:
    """Ensure a directory exists, creating it if necessary."""
    path = resolve_path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_file_path(filename: str, subdir: str = None) -> Path:
    """Generate a safe file path within a subdirectory."""
    if subdir:
        base_dir = get_project_root() / subdir
    else:
        base_dir = get_project_root()
    
    base_dir = ensure_dir(base_dir)
    return base_dir / filename
