"""Data loader for UNSW-NB15 and other datasets."""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import logging

from ..utils.logger import get_logger
from ..utils.paths import get_raw_data_dir, get_sample_data_dir
from ..utils.helpers import detect_label_column, clean_column_name
from ..utils.constants import LABEL_COLUMN_VARIANTS, UNSW_NB15_FEATURES

logger = get_logger(__name__)


class DatasetLoader:
    """Load and validate cybersecurity datasets."""
    
    def __init__(self):
        """Initialize the dataset loader."""
        self.raw_data_dir = get_raw_data_dir()
        self.sample_data_dir = get_sample_data_dir()
        self.supported_datasets = ["UNSW-NB15", "synthetic"]
    
    def load_dataset(self, 
                     dataset_name: str = "synthetic",
                     file_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
        """Load a dataset by name or file path."""
        logger.info(f"Loading dataset: {dataset_name}")
        
        if file_path:
            return self.load_from_file(file_path)
        
        if dataset_name == "synthetic":
            return self.load_synthetic_data()
        elif dataset_name == "UNSW-NB15":
            return self.load_unsw_nb15()
        else:
            raise ValueError(f"Unsupported dataset: {dataset_name}")
    
    def load_from_file(self, file_path: Union[str, Path]) -> pd.DataFrame:
        """Load dataset from a specific file path."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        logger.info(f"Loading data from {file_path}")
        
        # Determine file type and load accordingly
        if file_path.suffix == '.csv':
            df = pd.read_csv(file_path)
        elif file_path.suffix == '.parquet':
            df = pd.read_parquet(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_path.suffix}")
        
        logger.info(f"Loaded {len(df)} rows from {file_path}")
        return df
    
    def load_synthetic_data(self) -> pd.DataFrame:
        """Load synthetic sample data."""
        synthetic_file = self.sample_data_dir / "synthetic_alerts.csv"
        
        if not synthetic_file.exists():
            raise FileNotFoundError(
                f"Synthetic data not found at {synthetic_file}. "
                "Run python scripts/generate_synthetic_data.py first."
            )
        
        return self.load_from_file(synthetic_file)
    
    def load_unsw_nb15(self, 
                      training_file: Optional[Union[str, Path]] = None,
                      testing_file: Optional[Union[str, Path]] = None) -> pd.DataFrame:
        """Load UNSW-NB15 dataset."""
        if training_file is None:
            training_file = self.raw_data_dir / "UNSW_NB15_training-set.csv"
        
        if testing_file is None:
            testing_file = self.raw_data_dir / "UNSW_NB15_testing-set.csv"
        
        training_file = Path(training_file)
        testing_file = Path(testing_file)
        
        # Load training data
        if training_file.exists():
            train_df = self.load_from_file(training_file)
            logger.info(f"Loaded UNSW-NB15 training data: {len(train_df)} rows")
        else:
            logger.warning(f"UNSW-NB15 training file not found: {training_file}")
            train_df = pd.DataFrame()
        
        # Load testing data
        if testing_file.exists():
            test_df = self.load_from_file(testing_file)
            logger.info(f"Loaded UNSW-NB15 testing data: {len(test_df)} rows")
        else:
            logger.warning(f"UNSW-NB15 testing file not found: {testing_file}")
            test_df = pd.DataFrame()
        
        # Combine if both exist
        if not train_df.empty and not test_df.empty:
            train_df['dataset_split'] = 'train'
            test_df['dataset_split'] = 'test'
            combined_df = pd.concat([train_df, test_df], ignore_index=True)
            logger.info(f"Combined UNSW-NB15 data: {len(combined_df)} rows")
            return combined_df
        elif not train_df.empty:
            return train_df
        elif not test_df.empty:
            return test_df
        else:
            raise FileNotFoundError(
                "No UNSW-NB15 files found. Please place training and/or testing CSV files "
                f"in {self.raw_data_dir}"
            )
    
    def list_available_datasets(self) -> List[str]:
        """List available datasets in the raw data directory."""
        available = []
        
        if (self.sample_data_dir / "synthetic_alerts.csv").exists():
            available.append("synthetic")
        
        if (self.raw_data_dir / "UNSW_NB15_training-set.csv").exists():
            available.append("UNSW-NB15")
        
        # Check for other CSV files
        for csv_file in self.raw_data_dir.glob("*.csv"):
            if csv_file.name not in ["UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"]:
                available.append(csv_file.stem)
        
        return available
    
    def get_dataset_info(self, df: pd.DataFrame) -> Dict:
        """Get information about the loaded dataset."""
        info = {
            'rows': len(df),
            'columns': len(df.columns),
            'column_names': df.columns.tolist(),
            'memory_usage': df.memory_usage(deep=True).sum() / 1024**2,  # MB
            'missing_values': df.isnull().sum().to_dict(),
            'data_types': df.dtypes.astype(str).to_dict(),
            'label_column': detect_label_column(df.columns.tolist())
        }
        
        # Add label distribution if label column exists
        if info['label_column']:
            label_col = info['label_column']
            info['label_distribution'] = df[label_col].value_counts().to_dict()
        
        return info


class UNSWNB15Adapter:
    """Adapter for UNSW-NB15 dataset specific processing."""
    
    def __init__(self):
        """Initialize the UNSW-NB15 adapter."""
        self.expected_features = UNSW_NB15_FEATURES
        self.label_column_variants = LABEL_COLUMN_VARIANTS
    
    def standardize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardize column names to match expected format."""
        logger.info("Standardizing column names")
        
        # Create a mapping of current columns to standard names
        column_mapping = {}
        for col in df.columns:
            standardized = clean_column_name(col)
            column_mapping[col] = standardized
        
        # Rename columns
        df = df.rename(columns=column_mapping)
        
        logger.info(f"Standardized columns: {df.columns.tolist()}")
        return df
    
    def detect_label_column(self, df: pd.DataFrame) -> Optional[str]:
        """Detect the label column in the dataframe."""
        columns_lower = [col.lower() for col in df.columns]
        
        for variant in self.label_column_variants:
            if variant.lower() in columns_lower:
                original_col = df.columns[columns_lower.index(variant.lower())]
                logger.info(f"Detected label column: {original_col}")
                return original_col
        
        logger.warning("No label column detected")
        return None
    
    def validate_schema(self, df: pd.DataFrame) -> Tuple[bool, List[str]]:
        """Validate dataframe schema against expected features."""
        logger.info("Validating dataset schema")
        
        missing_features = []
        df_columns_lower = [col.lower() for col in df.columns]
        
        for feature in self.expected_features:
            feature_lower = feature.lower()
            if feature_lower not in df_columns_lower:
                missing_features.append(feature)
        
        if missing_features:
            logger.warning(f"Missing expected features: {missing_features}")
            return False, missing_features
        
        logger.info("Schema validation passed")
        return True, []
    
    def separate_features_labels(self, 
                                 df: pd.DataFrame,
                                 label_column: Optional[str] = None) -> Tuple[pd.DataFrame, Optional[pd.Series]]:
        """Separate features and labels."""
        if label_column is None:
            label_column = self.detect_label_column(df)
        
        if label_column and label_column in df.columns:
            labels = df[label_column].copy()
            features = df.drop(columns=[label_column])
            logger.info(f"Separated features and labels using column: {label_column}")
        else:
            labels = None
            features = df.copy()
            logger.info("No label column found, returning features only")
        
        return features, labels
    
    def get_attack_categories(self, df: pd.DataFrame, label_column: str) -> List[str]:
        """Get unique attack categories from the dataset."""
        if label_column in df.columns:
            categories = df[label_column].dropna().unique().tolist()
            logger.info(f"Found attack categories: {categories}")
            return categories
        return []


def load_data_for_training(dataset_name: str = "synthetic",
                          file_path: Optional[Union[str, Path]] = None) -> Tuple[pd.DataFrame, Optional[pd.Series], Dict]:
    """Load and prepare data for training."""
    loader = DatasetLoader()
    
    # Load dataset
    df = loader.load_dataset(dataset_name, file_path)
    
    # Get dataset info
    info = loader.get_dataset_info(df)
    
    # For UNSW-NB15, use adapter
    if dataset_name == "UNSW-NB15":
        adapter = UNSWNB15Adapter()
        df = adapter.standardize_columns(df)
        label_column = adapter.detect_label_column(df)
        features, labels = adapter.separate_features_labels(df, label_column)
        is_valid, missing = adapter.validate_schema(df)
        info['schema_valid'] = is_valid
        info['missing_features'] = missing
    else:
        # For synthetic data, simple separation
        label_column = detect_label_column(df.columns.tolist())
        if label_column:
            labels = df[label_column].copy()
            features = df.drop(columns=[label_column])
        else:
            labels = None
            features = df.copy()
        info['schema_valid'] = True
        info['missing_features'] = []
    
    return features, labels, info


if __name__ == "__main__":
    # Test data loading
    loader = DatasetLoader()
    
    # List available datasets
    available = loader.list_available_datasets()
    print(f"Available datasets: {available}")
    
    # Load synthetic data
    if "synthetic" in available:
        df = loader.load_synthetic_data()
        info = loader.get_dataset_info(df)
        print(f"Dataset info: {info}")
