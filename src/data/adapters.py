"""Dataset adapters for different cybersecurity datasets."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
import pandas as pd
import logging

from ..utils.logger import get_logger

logger = get_logger(__name__)


class DatasetAdapter(ABC):
    """Abstract base class for dataset adapters."""
    
    def __init__(self):
        """Initialize the dataset adapter."""
        self.dataset_name = "base"
        self.expected_features = []
        self.label_columns = []
    
    @abstractmethod
    def load(self, file_path: str) -> pd.DataFrame:
        """Load dataset from file."""
        pass
    
    @abstractmethod
    def standardize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize dataset to common format."""
        pass
    
    @abstractmethod
    def get_label_column(self, df: pd.DataFrame) -> Optional[str]:
        """Get the label column name."""
        pass
    
    @abstractmethod
    def get_attack_categories(self, df: pd.DataFrame) -> List[str]:
        """Get attack categories."""
        pass


class UNSWNB15Adapter(DatasetAdapter):
    """Adapter for UNSW-NB15 dataset."""
    
    def __init__(self):
        """Initialize UNSW-NB15 adapter."""
        super().__init__()
        self.dataset_name = "UNSW-NB15"
        self.expected_features = [
            "srcip", "sport", "dstip", "dsport", "proto", "service", "state",
            "dur", "sbytes", "dbytes", "sttl", "dttl", "sload", "dload", "sloss",
            "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb",
            "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
            "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
            "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
            "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
            "ct_src_dport_ltm", "attack_cat", "label"
        ]
        self.label_columns = ["label", "attack_cat"]
    
    def load(self, file_path: str) -> pd.DataFrame:
        """Load UNSW-NB15 dataset from CSV file."""
        logger.info(f"Loading UNSW-NB15 dataset from {file_path}")
        
        # UNSW-NB15 files may have different encodings
        try:
            df = pd.read_csv(file_path)
        except UnicodeDecodeError:
            logger.warning("UTF-8 decoding failed, trying latin-1")
            df = pd.read_csv(file_path, encoding='latin-1')
        
        logger.info(f"Loaded {len(df)} rows from UNSW-NB15 dataset")
        return df
    
    def standardize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize UNSW-NB15 column names."""
        logger.info("Standardizing UNSW-NB15 column names")
        
        # Column name mapping for UNSW-NB15
        column_mapping = {
            'Source IP': 'srcip',
            'Source Port': 'sport',
            'Destination IP': 'dstip',
            'Destination Port': 'dsport',
            'Protocol': 'proto',
            'Service': 'service',
            'State': 'state',
            'Duration': 'dur',
            'Source Bytes': 'sbytes',
            'Destination Bytes': 'dbytes',
            'Source TTL': 'sttl',
            'Destination TTL': 'dttl',
            'Source Load': 'sload',
            'Destination Load': 'dload',
            'Source Loss': 'sloss',
            'Destination Loss': 'dloss',
            'Source Packets': 'sinpkt',
            'Destination Packets': 'dinpkt',
            'Source Jitter': 'sjit',
            'Destination Jitter': 'djit',
            'Source Window': 'swin',
            'Source TCP Base': 'stcpb',
            'Destination TCP Base': 'dtcpb',
            'Destination Window': 'dwin',
            'TCP RTT': 'tcprtt',
            'SYN ACK': 'synack',
            'ACK Dat': 'ackdat',
            'Source Mean': 'smean',
            'Destination Mean': 'dmean',
            'Transaction Depth': 'trans_depth',
            'Response Body Len': 'response_body_len',
            'CT State TTL': 'ct_state_ttl',
            'CT Destination LTm': 'ct_dst_ltm',
            'CT Source Destination LTm': 'ct_dst_src_ltm',
            'CT Source Port LTm': 'ct_src_dport_ltm',
            'CT Destination Port LTm': 'ct_dst_sport_ltm',
            'CT FTP Command': 'ct_ftp_cmd',
            'CT Service Source': 'ct_srv_src',
            'CT Service Destination': 'ct_srv_dst',
            'CT Destination LTm (2)': 'ct_dst_ltm',
            'CT Source LTm': 'ct_src_ltm',
            'Attack Category': 'attack_cat',
            'Label': 'label'
        }
        
        # Apply mapping for existing columns
        for old_name, new_name in column_mapping.items():
            if old_name in df.columns:
                df = df.rename(columns={old_name: new_name})
        
        # Lowercase all column names
        df.columns = [col.lower() for col in df.columns]
        
        logger.info(f"Standardized columns: {df.columns.tolist()}")
        return df
    
    def get_label_column(self, df: pd.DataFrame) -> Optional[str]:
        """Get the label column for UNSW-NB15."""
        # Priority: label > attack_cat
        if 'label' in df.columns:
            return 'label'
        elif 'attack_cat' in df.columns:
            return 'attack_cat'
        return None
    
    def get_attack_categories(self, df: pd.DataFrame) -> List[str]:
        """Get attack categories from UNSW-NB15."""
        if 'attack_cat' in df.columns:
            categories = df['attack_cat'].dropna().unique().tolist()
            return categories
        return []


class SyntheticAdapter(DatasetAdapter):
    """Adapter for synthetic data."""
    
    def __init__(self):
        """Initialize synthetic data adapter."""
        super().__init__()
        self.dataset_name = "synthetic"
        self.expected_features = [
            "timestamp", "source_ip", "destination_ip", "source_port",
            "destination_port", "protocol", "service", "duration",
            "source_bytes", "destination_bytes", "source_packets",
            "destination_packets", "attack_category", "label"
        ]
        self.label_columns = ["label", "attack_category"]
    
    def load(self, file_path: str) -> pd.DataFrame:
        """Load synthetic data from CSV file."""
        logger.info(f"Loading synthetic data from {file_path}")
        df = pd.read_csv(file_path)
        logger.info(f"Loaded {len(df)} rows from synthetic data")
        return df
    
    def standardize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize synthetic data column names."""
        logger.info("Standardizing synthetic data column names")
        
        # Column name mapping
        column_mapping = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'destination_ip': 'destination_ip',
            'source_port': 'source_port',
            'destination_port': 'destination_port',
            'protocol': 'protocol',
            'service': 'service',
            'duration': 'duration',
            'source_bytes': 'source_bytes',
            'destination_bytes': 'destination_bytes',
            'source_packets': 'source_packets',
            'destination_packets': 'destination_packets',
            'attack_category': 'attack_category',
            'label': 'label'
        }
        
        # Apply mapping
        df = df.rename(columns={col: col for col in df.columns if col in column_mapping})
        
        # Lowercase all column names
        df.columns = [col.lower() for col in df.columns]
        
        logger.info(f"Standardized columns: {df.columns.tolist()}")
        return df
    
    def get_label_column(self, df: pd.DataFrame) -> Optional[str]:
        """Get the label column for synthetic data."""
        if 'label' in df.columns:
            return 'label'
        elif 'attack_category' in df.columns:
            return 'attack_category'
        return None
    
    def get_attack_categories(self, df: pd.DataFrame) -> List[str]:
        """Get attack categories from synthetic data."""
        if 'attack_category' in df.columns:
            categories = df['attack_category'].dropna().unique().tolist()
            return categories
        return []


class CICIDS2017Adapter(DatasetAdapter):
    """Adapter for CIC-IDS2017 dataset (future implementation)."""
    
    def __init__(self):
        """Initialize CIC-IDS2017 adapter."""
        super().__init__()
        self.dataset_name = "CIC-IDS2017"
        # Future: Add expected features for CIC-IDS2017
    
    def load(self, file_path: str) -> pd.DataFrame:
        """Load CIC-IDS2017 dataset (future implementation)."""
        logger.warning("CIC-IDS2017 adapter not yet implemented")
        raise NotImplementedError("CIC-IDS2017 adapter not yet implemented")
    
    def standardize(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize CIC-IDS2017 dataset (future implementation)."""
        logger.warning("CIC-IDS2017 adapter not yet implemented")
        raise NotImplementedError("CIC-IDS2017 adapter not yet implemented")
    
    def get_label_column(self, df: pd.DataFrame) -> Optional[str]:
        """Get label column for CIC-IDS2017 (future implementation)."""
        logger.warning("CIC-IDS2017 adapter not yet implemented")
        raise NotImplementedError("CIC-IDS2017 adapter not yet implemented")
    
    def get_attack_categories(self, df: pd.DataFrame) -> List[str]:
        """Get attack categories for CIC-IDS2017 (future implementation)."""
        logger.warning("CIC-IDS2017 adapter not yet implemented")
        raise NotImplementedError("CIC-IDS2017 adapter not yet implemented")


def get_adapter(dataset_name: str) -> DatasetAdapter:
    """Get the appropriate adapter for a dataset."""
    adapters = {
        'UNSW-NB15': UNSWNB15Adapter,
        'synthetic': SyntheticAdapter,
        'CIC-IDS2017': CICIDS2017Adapter
    }
    
    adapter_class = adapters.get(dataset_name)
    if adapter_class:
        return adapter_class()
    else:
        logger.warning(f"No adapter found for dataset: {dataset_name}, using base adapter")
        return DatasetAdapter()


def register_adapter(dataset_name: str, adapter_class: type):
    """Register a custom dataset adapter."""
    # This would be used for future extensibility
    logger.info(f"Registering adapter for dataset: {dataset_name}")
    # Implementation would add to the adapters dictionary
    pass
