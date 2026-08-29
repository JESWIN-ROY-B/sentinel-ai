"""Tests for data validation."""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path

from src.utils.helpers import detect_label_column, clean_column_name, validate_ip


class TestDataValidation:
    """Test cases for data validation functions."""
    
    def test_detect_label_column(self):
        """Test label column detection."""
        # Test with standard label column
        columns = ["srcip", "dstip", "proto", "label"]
        assert detect_label_column(columns) == "label"
        
        # Test with Label (capitalized)
        columns = ["srcip", "dstip", "proto", "Label"]
        assert detect_label_column(columns) == "Label"
        
        # Test with attack_cat
        columns = ["srcip", "dstip", "proto", "attack_cat"]
        assert detect_label_column(columns) == "attack_cat"
        
        # Test with no label column
        columns = ["srcip", "dstip", "proto", "service"]
        assert detect_label_column(columns) is None
    
    def test_clean_column_name(self):
        """Test column name cleaning."""
        assert clean_column_name("Source IP") == "source_ip"
        assert clean_column_name("Source-IP") == "source_ip"
        assert clean_column_name("Source.IP") == "source_ip"
        assert clean_column_name("  Source IP  ") == "source_ip"
        assert clean_column_name(None) == "unknown"
        assert clean_column_name(np.nan) == "unknown"
    
    def test_validate_ip(self):
        """Test IP validation."""
        # Valid IPv4
        assert validate_ip("192.168.1.1") == True
        assert validate_ip("10.0.0.1") == True
        assert validate_ip("172.16.0.1") == True
        
        # Invalid IPv4
        assert validate_ip("256.168.1.1") == False
        assert validate_ip("192.168.1") == False
        assert validate_ip("192.168.1.1.1") == False
        
        # IPv6 (basic check)
        assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == True
        
        # Invalid inputs
        assert validate_ip(None) == False
        assert validate_ip("") == False
        assert validate_ip("not_an_ip") == False


class TestSchemaValidation:
    """Test cases for schema validation."""
    
    def test_dataframe_schema_validation(self):
        """Test DataFrame schema validation."""
        # Create a valid dataframe
        valid_df = pd.DataFrame({
            'srcip': ['192.168.1.1', '10.0.0.1'],
            'dstip': ['192.168.1.2', '10.0.0.2'],
            'proto': ['tcp', 'udp'],
            'label': [0, 1]
        })
        
        assert len(valid_df) == 2
        assert 'srcip' in valid_df.columns
        assert 'label' in valid_df.columns
        
        # Test with missing columns
        invalid_df = pd.DataFrame({
            'srcip': ['192.168.1.1'],
            'dstip': ['192.168.1.2']
        })
        
        assert 'label' not in invalid_df.columns
    
    def test_data_type_validation(self):
        """Test data type validation."""
        df = pd.DataFrame({
            'int_col': [1, 2, 3],
            'float_col': [1.0, 2.0, 3.0],
            'str_col': ['a', 'b', 'c'],
            'bool_col': [True, False, True]
        })
        
        assert pd.api.types.is_integer_dtype(df['int_col'])
        assert pd.api.types.is_float_dtype(df['float_col'])
        assert pd.api.types.is_string_dtype(df['str_col'])
        assert pd.api.types.is_bool_dtype(df['bool_col'])
    
    def test_missing_value_detection(self):
        """Test missing value detection."""
        df = pd.DataFrame({
            'col1': [1, 2, None, 4],
            'col2': [1.0, np.nan, 3.0, 4.0],
            'col3': ['a', None, 'c', 'd']
        })
        
        assert df['col1'].isna().sum() == 1
        assert df['col2'].isna().sum() == 1
        assert df['col3'].isna().sum() == 1
    
    def test_duplicate_detection(self):
        """Test duplicate row detection."""
        df = pd.DataFrame({
            'col1': [1, 2, 2, 3],
            'col2': ['a', 'b', 'b', 'c']
        })
        
        duplicates = df.duplicated()
        assert duplicates.sum() == 2  # Two duplicate rows


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
