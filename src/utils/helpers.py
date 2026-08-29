"""Helper functions for Sentinel AI."""

import pandas as pd
import numpy as np
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import hashlib
import re


def safe_float(value: Any) -> float:
    """Safely convert a value to float, handling edge cases."""
    try:
        if pd.isna(value) or value is None:
            return 0.0
        if isinstance(value, (int, float)):
            if np.isinf(value):
                return 0.0
            return float(value)
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def safe_int(value: Any) -> int:
    """Safely convert a value to int, handling edge cases."""
    try:
        if pd.isna(value) or value is None:
            return 0
        if isinstance(value, (int, float)):
            if np.isinf(value):
                return 0
            return int(value)
        return int(value)
    except (ValueError, TypeError):
        return 0


def safe_str(value: Any) -> str:
    """Safely convert a value to string, handling edge cases."""
    if pd.isna(value) or value is None:
        return ""
    return str(value)


def normalize_score(score: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """Normalize a score to a specified range."""
    try:
        score = safe_float(score)
        if max_val == min_val:
            return min_val
        normalized = (score - min_val) / (max_val - min_val) * 100
        return max(0.0, min(100.0, normalized))
    except (ValueError, TypeError):
        return 0.0


def calculate_risk_score(components: Dict[str, float], weights: Dict[str, float]) -> float:
    """Calculate weighted risk score from components."""
    total_score = 0.0
    total_weight = 0.0
    
    for component, value in components.items():
        weight = weights.get(component, 0.0)
        normalized_value = normalize_score(value)
        total_score += normalized_value * weight
        total_weight += weight
    
    if total_weight == 0:
        return 0.0
    
    return normalize_score(total_score / total_weight)


def determine_severity(risk_score: float, thresholds: Dict[str, int]) -> str:
    """Determine severity level from risk score."""
    if risk_score >= thresholds.get('critical', 85):
        return "Critical"
    elif risk_score >= thresholds.get('high', 70):
        return "High"
    elif risk_score >= thresholds.get('medium', 40):
        return "Medium"
    else:
        return "Low"


def generate_incident_id() -> str:
    """Generate a unique incident ID."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_hash = hashlib.md5(timestamp.encode()).hexdigest()[:8].upper()
    return f"INC-{timestamp}-{random_hash}"


def mask_ip(ip: str, mask_chars: int = 3) -> str:
    """Mask an IP address for privacy in demo mode."""
    if not ip or pd.isna(ip):
        return "unknown"
    
    # Check if it's an IPv4 address
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(ipv4_pattern, str(ip))
    if match:
        parts = match.groups()
        return f"{parts[0]}.{'*' * mask_chars}.{parts[2]}.{'*' * mask_chars}"
    
    # Check if it's an IPv6 address (simplified)
    if ':' in str(ip):
        parts = str(ip).split(':')
        return f"{parts[0]}:{'*' * mask_chars}:{parts[2]}:{'*' * mask_chars}"
    
    # Fallback for non-IP strings
    return str(ip)[:mask_chars] + '*' * (len(str(ip)) - mask_chars)


def timestamp_to_datetime(timestamp: Union[str, float, int, pd.Timestamp]) -> datetime:
    """Convert various timestamp formats to datetime object."""
    if pd.isna(timestamp):
        return datetime.now()
    
    if isinstance(timestamp, datetime):
        return timestamp
    
    if isinstance(timestamp, pd.Timestamp):
        return timestamp.to_pydatetime()
    
    if isinstance(timestamp, (int, float)):
        try:
            return datetime.fromtimestamp(timestamp)
        except (ValueError, TypeError, OSError):
            return datetime.now()
    
    if isinstance(timestamp, str):
        try:
            # Try common formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                try:
                    return datetime.strptime(timestamp, fmt)
                except ValueError:
                    continue
        except (ValueError, TypeError):
            pass
    
    return datetime.now()


def format_timedelta(delta_seconds: float) -> str:
    """Format a time delta in seconds to human-readable string."""
    if delta_seconds < 60:
        return f"{delta_seconds:.1f}s"
    elif delta_seconds < 3600:
        minutes = delta_seconds / 60
        return f"{minutes:.1f}m"
    elif delta_seconds < 86400:
        hours = delta_seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = delta_seconds / 86400
        return f"{days:.1f}d"


def validate_ip(ip: str) -> bool:
    """Validate if a string is a valid IP address."""
    if not ip or pd.isna(ip):
        return False
    
    ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if re.match(ipv4_pattern, str(ip)):
        parts = str(ip).split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    # Basic IPv6 check
    if ':' in str(ip):
        return True
    
    return False


def clean_column_name(name: str) -> str:
    """Clean and standardize column names."""
    if pd.isna(name):
        return "unknown"
    
    name = str(name).strip().lower()
    # Replace spaces and special characters with underscores
    name = re.sub(r'[^\w]', '_', name)
    # Remove consecutive underscores
    name = re.sub(r'_+', '_', name)
    # Remove leading/trailing underscores
    name = name.strip('_')
    
    return name


def detect_label_column(columns: List[str]) -> Optional[str]:
    """Detect the label column from a list of column names."""
    from .constants import LABEL_COLUMN_VARIANTS
    
    columns_lower = [col.lower() for col in columns]
    
    for variant in LABEL_COLUMN_VARIANTS:
        if variant.lower() in columns_lower:
            return columns[columns_lower.index(variant.lower())]
    
    return None


def create_baseline_comparison(current_value: float, baseline_value: float, feature_name: str) -> str:
    """Create a human-readable baseline comparison string."""
    if pd.isna(current_value) or pd.isna(baseline_value):
        return f"{feature_name}: Unable to compare (missing data)"
    
    diff = current_value - baseline_value
    percent_diff = (diff / baseline_value * 100) if baseline_value != 0 else 0
    
    if abs(percent_diff) < 10:
        return f"{feature_name}: Normal (within 10% of baseline)"
    elif percent_diff > 0:
        return f"{feature_name}: Elevated (+{percent_diff:.1f}% above baseline)"
    else:
        return f"{feature_name}: Reduced ({percent_diff:.1f}% below baseline)"


def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split a list into chunks of specified size."""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple dictionaries, with later dicts taking precedence."""
    result = {}
    for d in dicts:
        result.update(d)
    return result


def format_number(num: float, precision: int = 2) -> str:
    """Format a number with appropriate precision and units."""
    if pd.isna(num):
        return "N/A"
    
    if abs(num) >= 1_000_000:
        return f"{num/1_000_000:.{precision}f}M"
    elif abs(num) >= 1_000:
        return f"{num/1_000:.{precision}f}K"
    else:
        return f"{num:.{precision}f}"


def is_synthetic_mode() -> bool:
    """Check if the system is running in synthetic demo mode."""
    from .config import config
    return config.env.get('synthetic_data_enabled', True)


def validate_threshold(threshold: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """Validate and clamp a threshold value."""
    threshold = safe_float(threshold)
    return max(min_val, min(max_val, threshold))
