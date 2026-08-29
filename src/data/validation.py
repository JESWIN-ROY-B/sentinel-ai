"""Data validation utilities for cybersecurity datasets."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
import logging

from ..utils.logger import get_logger
from ..utils.helpers import validate_ip, clean_column_name
from ..utils.constants import UNSW_NB15_FEATURES, LABEL_COLUMN_VARIANTS

logger = get_logger(__name__)


class DataValidator:
    """Validate cybersecurity data for quality and schema compliance."""
    
    def __init__(self):
        """Initialize the data validator."""
        self.validation_results = {}
        self.errors = []
        self.warnings = []
    
    def validate_dataframe(self, df: pd.DataFrame, expected_schema: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform comprehensive validation on a dataframe."""
        logger.info("Starting dataframe validation")
        
        self.validation_results = {
            'is_valid': True,
            'row_count': len(df),
            'column_count': len(df.columns),
            'columns': df.columns.tolist(),
            'data_types': {col: str(dtype) for col, dtype in df.dtypes.items()},
            'missing_values': {},
            'duplicate_rows': 0,
            'infinite_values': {},
            'schema_compliance': True,
            'missing_columns': [],
            'extra_columns': [],
            'label_column': None,
            'errors': [],
            'warnings': []
        }
        
        # Check for empty dataframe
        if len(df) == 0:
            self._add_error("Dataframe is empty")
            self.validation_results['is_valid'] = False
            return self.validation_results
        
        # Check schema compliance
        if expected_schema:
            self._validate_schema(df, expected_schema)
        
        # Check for missing values
        self._check_missing_values(df)
        
        # Check for duplicate rows
        self._check_duplicates(df)
        
        # Check for infinite values
        self._check_infinite_values(df)
        
        # Detect label column
        self._detect_label_column(df)
        
        # Validate IP addresses if present
        self._validate_ip_columns(df)
        
        # Validate numerical ranges
        self._validate_numerical_ranges(df)
        
        # Overall validity
        if self.errors:
            self.validation_results['is_valid'] = False
        
        self.validation_results['errors'] = self.errors
        self.validation_results['warnings'] = self.warnings
        
        logger.info(f"Validation complete: is_valid={self.validation_results['is_valid']}")
        return self.validation_results
    
    def _validate_schema(self, df: pd.DataFrame, expected_schema: List[str]):
        """Validate dataframe schema against expected columns."""
        df_columns_lower = [clean_column_name(col) for col in df.columns]
        expected_lower = [clean_column_name(col) for col in expected_schema]
        
        # Check for missing columns
        missing = [col for col in expected_schema if clean_column_name(col) not in df_columns_lower]
        if missing:
            self._add_error(f"Missing expected columns: {missing}")
            self.validation_results['missing_columns'] = missing
            self.validation_results['schema_compliance'] = False
        
        # Check for extra columns
        extra = [col for col in df.columns if clean_column_name(col) not in expected_lower]
        if extra:
            self._add_warning(f"Extra columns found: {extra}")
            self.validation_results['extra_columns'] = extra
    
    def _check_missing_values(self, df: pd.DataFrame):
        """Check for missing values in each column."""
        missing_counts = df.isnull().sum()
        missing_percentages = (missing_counts / len(df)) * 100
        
        for col in df.columns:
            if missing_counts[col] > 0:
                self.validation_results['missing_values'][col] = {
                    'count': int(missing_counts[col]),
                    'percentage': float(missing_percentages[col])
                }
                
                if missing_percentages[col] > 50:
                    self._add_warning(f"Column '{col}' has {missing_percentages[col]:.1f}% missing values")
                elif missing_percentages[col] > 90:
                    self._add_error(f"Column '{col}' has {missing_percentages[col]:.1f}% missing values")
    
    def _check_duplicates(self, df: pd.DataFrame):
        """Check for duplicate rows."""
        duplicate_count = df.duplicated().sum()
        self.validation_results['duplicate_rows'] = int(duplicate_count)
        
        if duplicate_count > 0:
            duplicate_percentage = (duplicate_count / len(df)) * 100
            self._add_warning(f"Found {duplicate_count} duplicate rows ({duplicate_percentage:.1f}%)")
    
    def _check_infinite_values(self, df: pd.DataFrame):
        """Check for infinite values in numerical columns."""
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numerical_cols:
            inf_count = np.isinf(df[col]).sum()
            if inf_count > 0:
                self.validation_results['infinite_values'][col] = int(inf_count)
                self._add_warning(f"Column '{col}' contains {inf_count} infinite values")
    
    def _detect_label_column(self, df: pd.DataFrame):
        """Detect the label column in the dataframe."""
        columns_lower = [col.lower() for col in df.columns]
        
        for variant in LABEL_COLUMN_VARIANTS:
            if variant.lower() in columns_lower:
                original_col = df.columns[columns_lower.index(variant.lower())]
                self.validation_results['label_column'] = original_col
                logger.info(f"Detected label column: {original_col}")
                return
        
        self._add_warning("No label column detected")
    
    def _validate_ip_columns(self, df: pd.DataFrame):
        """Validate IP address columns if present."""
        ip_columns = [col for col in df.columns if 'ip' in col.lower()]
        
        for col in ip_columns:
            if df[col].dtype == 'object':
                # Sample some values to check
                sample_ips = df[col].dropna().head(100)
                invalid_ips = []
                
                for ip in sample_ips:
                    if not validate_ip(ip):
                        invalid_ips.append(ip)
                        if len(invalid_ips) >= 5:  # Limit sample
                            break
                
                if invalid_ips:
                    self._add_warning(f"Column '{col}' may contain invalid IP addresses")
    
    def _validate_numerical_ranges(self, df: pd.DataFrame):
        """Validate numerical columns for reasonable ranges."""
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        
        for col in numerical_cols:
            # Check for extreme values
            col_min = df[col].min()
            col_max = df[col].max()
            
            # Skip if all NaN
            if pd.isna(col_min) or pd.isna(col_max):
                continue
            
            # Check for reasonable ranges (heuristic)
            if abs(col_max) > 1e10:
                self._add_warning(f"Column '{col}' has extremely large values: max={col_max}")
            
            if abs(col_min) > 1e10:
                self._add_warning(f"Column '{col}' has extremely small values: min={col_min}")
    
    def _add_error(self, message: str):
        """Add an error message."""
        self.errors.append(message)
        logger.error(f"Validation error: {message}")
    
    def _add_warning(self, message: str):
        """Add a warning message."""
        self.warnings.append(message)
        logger.warning(f"Validation warning: {message}")
    
    def get_validation_report(self) -> str:
        """Generate a human-readable validation report."""
        report = []
        report.append("=" * 50)
        report.append("DATA VALIDATION REPORT")
        report.append("=" * 50)
        
        # Overall status
        status = "VALID" if self.validation_results.get('is_valid', False) else "INVALID"
        report.append(f"Overall Status: {status}")
        report.append(f"Row Count: {self.validation_results.get('row_count', 0)}")
        report.append(f"Column Count: {self.validation_results.get('column_count', 0)}")
        report.append("")
        
        # Schema compliance
        report.append("Schema Compliance:")
        report.append(f"  Compliant: {self.validation_results.get('schema_compliance', False)}")
        if self.validation_results.get('missing_columns'):
            report.append(f"  Missing Columns: {self.validation_results['missing_columns']}")
        if self.validation_results.get('extra_columns'):
            report.append(f"  Extra Columns: {self.validation_results['extra_columns']}")
        report.append("")
        
        # Missing values
        if self.validation_results.get('missing_values'):
            report.append("Missing Values:")
            for col, info in self.validation_results['missing_values'].items():
                report.append(f"  {col}: {info['count']} ({info['percentage']:.1f}%)")
            report.append("")
        
        # Duplicates
        report.append(f"Duplicate Rows: {self.validation_results.get('duplicate_rows', 0)}")
        report.append("")
        
        # Infinite values
        if self.validation_results.get('infinite_values'):
            report.append("Infinite Values:")
            for col, count in self.validation_results['infinite_values'].items():
                report.append(f"  {col}: {count}")
            report.append("")
        
        # Label column
        label_col = self.validation_results.get('label_column')
        report.append(f"Label Column: {label_col if label_col else 'None detected'}")
        report.append("")
        
        # Errors
        if self.errors:
            report.append("Errors:")
            for error in self.errors:
                report.append(f"  - {error}")
            report.append("")
        
        # Warnings
        if self.warnings:
            report.append("Warnings:")
            for warning in self.warnings:
                report.append(f"  - {warning}")
            report.append("")
        
        report.append("=" * 50)
        
        return "\n".join(report)


def validate_upload(file_info: Dict[str, Any], max_size_mb: int = 100) -> Tuple[bool, str]:
    """Validate an uploaded file before processing."""
    errors = []
    
    # Check file size
    file_size = file_info.get('size', 0)
    max_size_bytes = max_size_mb * 1024 * 1024
    
    if file_size > max_size_bytes:
        errors.append(f"File size ({file_size / 1024 / 1024:.1f}MB) exceeds maximum ({max_size_mb}MB)")
    
    # Check file extension
    file_name = file_info.get('name', '')
    allowed_extensions = ['.csv', '.parquet']
    
    if not any(file_name.lower().endswith(ext) for ext in allowed_extensions):
        errors.append(f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}")
    
    # Check file name
    if not file_name:
        errors.append("File name is empty")
    
    is_valid = len(errors) == 0
    error_message = "; ".join(errors) if errors else "File validation passed"
    
    return is_valid, error_message


def validate_prediction_input(input_data: Dict[str, Any], expected_features: List[str]) -> Tuple[bool, str]:
    """Validate input data for prediction."""
    errors = []
    
    # Check if input is a dictionary
    if not isinstance(input_data, dict):
        errors.append("Input must be a dictionary")
        return False, "; ".join(errors)
    
    # Check for missing features
    missing_features = set(expected_features) - set(input_data.keys())
    if missing_features:
        errors.append(f"Missing required features: {missing_features}")
    
    # Check for extra features
    extra_features = set(input_data.keys()) - set(expected_features)
    if extra_features:
        errors.append(f"Unexpected features provided: {extra_features}")
    
    # Check for None values in required features
    for feature in expected_features:
        if feature in input_data and input_data[feature] is None:
            errors.append(f"Feature '{feature}' has None value")
    
    is_valid = len(errors) == 0
    error_message = "; ".join(errors) if errors else "Input validation passed"
    
    return is_valid, error_message


if __name__ == "__main__":
    # Test validation
    from .loader import DatasetLoader
    
    loader = DatasetLoader()
    df = loader.load_synthetic_data()
    
    validator = DataValidator()
    results = validator.validate_dataframe(df)
    
    print(validator.get_validation_report())
