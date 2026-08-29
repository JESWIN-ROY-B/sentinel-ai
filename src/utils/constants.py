"""Constants for Sentinel AI."""

from enum import Enum


class AttackCategory(str, Enum):
    """UNSW-NB15 attack categories."""
    NORMAL = "Normal"
    FUZZERS = "Fuzzers"
    ANALYSIS = "Analysis"
    BACKDOORS = "Backdoors"
    DOS = "DoS"
    EXPLOITS = "Exploits"
    GENERIC = "Generic"
    RECONNAISSANCE = "Reconnaissance"
    SHELLCODE = "Shellcode"
    WORMS = "Worms"


class Severity(str, Enum):
    """Severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IncidentStatus(str, Enum):
    """Incident workflow statuses."""
    NEW = "New"
    UNDER_INVESTIGATION = "Under Investigation"
    ESCALATED = "Escalated"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"


class ModelType(str, Enum):
    """Model types."""
    BINARY = "binary"
    MULTICLASS = "multiclass"
    ANOMALY = "anomaly"


class PredictionLabel(str, Enum):
    """Prediction labels."""
    NORMAL = "Normal"
    ATTACK = "Attack"


# UNSW-NB15 feature columns (standardized names)
UNSW_NB15_FEATURES = [
    "srcip", "sport", "dstip", "dsport", "proto", "service", "state",
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sload", "dload", "sloss",
    "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb",
    "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
    "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
    "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
    "ct_src_dport_ltm", "attack_cat", "label"
]

# Label column variants
LABEL_COLUMN_VARIANTS = ["label", "Label", "attack_cat", "attackcat", "category"]

# Columns to exclude from training (leakage or identifiers)
LEAKAGE_COLUMNS = ["srcip", "dstip", "sport", "dsport", "stcpb", "dtcpb"]

# Numerical features for scaling
NUMERICAL_FEATURES = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sload", "dload", "sloss",
    "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "dwin", "tcprtt",
    "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "ct_ftp_cmd", "ct_srv_src",
    "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm"
]

# Categorical features for encoding
CATEGORICAL_FEATURES = ["proto", "service", "state"]

# Risk scoring component names
RISK_COMPONENTS = [
    "model_confidence",
    "anomaly_score", 
    "attack_severity",
    "asset_criticality",
    "user_privilege_risk",
    "alert_frequency",
    "threat_intel_reputation"
]

# Default values
DEFAULT_RANDOM_SEED = 42
DEFAULT_TEST_SIZE = 0.2
DEFAULT_VALIDATION_SIZE = 0.1
DEFAULT_ANOMALY_THRESHOLD = 50
DEFAULT_PREDICTION_THRESHOLD = 0.5

# File extensions
MODEL_EXTENSIONS = [".pkl", ".joblib", ".h5", ".json"]
DATA_EXTENSIONS = [".csv", ".parquet"]

# UI constants
MAX_DISPLAY_ALERTS = 1000
DEFAULT_REFRESH_INTERVAL = 30
DEMO_MODE_BADGE = "DEMO MODE"
