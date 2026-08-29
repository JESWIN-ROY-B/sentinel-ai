"""Tests for data preprocessing."""

import pytest
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder


class TestDataPreprocessing:
    """Test cases for data preprocessing functionality."""
    
    def test_handle_missing_values_mean(self):
        """Test missing value handling with mean strategy."""
        df = pd.DataFrame({
            'col1': [1, 2, np.nan, 4],
            'col2': [1.0, np.nan, 3.0, 4.0]
        })
        
        # Fill with mean
        df_filled = df.fillna(df.mean())
        
        assert df_filled['col1'].isna().sum() == 0
        assert df_filled['col2'].isna().sum() == 0
        assert df_filled.loc[2, 'col1'] == pytest.approx(2.33, rel=0.1)
    
    def test_handle_missing_values_median(self):
        """Test missing value handling with median strategy."""
        df = pd.DataFrame({
            'col1': [1, 2, np.nan, 4, 100]  # 100 is outlier
        })
        
        # Fill with median
        median_val = df['col1'].median()
        df_filled = df.fillna(median_val)
        
        assert df_filled['col1'].isna().sum() == 0
        assert df_filled.loc[2, 'col1'] == 2.0  # Median of [1,2,4,100]
    
    def test_handle_infinite_values(self):
        """Test infinite value handling."""
        df = pd.DataFrame({
            'col1': [1, 2, np.inf, -np.inf, 5]
        })
        
        # Replace infinite values
        df_clean = df.replace([np.inf, -np.inf], np.nan).fillna(0)
        
        assert not np.isinf(df_clean['col1']).any()
        assert df_clean.loc[2, 'col1'] == 0.0
        assert df_clean.loc[3, 'col1'] == 0.0
    
    def test_remove_duplicates(self):
        """Test duplicate row removal."""
        df = pd.DataFrame({
            'col1': [1, 2, 2, 3],
            'col2': ['a', 'b', 'b', 'c']
        })
        
        df_unique = df.drop_duplicates()
        
        assert len(df_unique) == 3
        assert len(df) == 4  # Original unchanged
    
    def test_categorical_encoding_label(self):
        """Test label encoding for categorical variables."""
        df = pd.DataFrame({
            'proto': ['tcp', 'udp', 'tcp', 'icmp']
        })
        
        encoder = LabelEncoder()
        df['proto_encoded'] = encoder.fit_transform(df['proto'])
        
        assert df['proto_encoded'].dtype in [np.int32, np.int64]
        assert len(df['proto_encoded'].unique()) == 3
    
    def test_categorical_encoding_onehot(self):
        """Test one-hot encoding for categorical variables."""
        df = pd.DataFrame({
            'proto': ['tcp', 'udp', 'tcp', 'icmp']
        })
        
        df_onehot = pd.get_dummies(df, columns=['proto'], prefix='proto')
        
        assert 'proto_tcp' in df_onehot.columns
        assert 'proto_udp' in df_onehot.columns
        assert 'proto_icmp' in df_onehot.columns
    
    def test_numerical_scaling_standard(self):
        """Test standard scaling for numerical variables."""
        df = pd.DataFrame({
            'col1': [1, 2, 3, 4, 100]
        })
        
        scaler = StandardScaler()
        df_scaled = pd.DataFrame(
            scaler.fit_transform(df),
            columns=df.columns
        )
        
        # Check that mean is approximately 0 and std is approximately 1
        assert abs(df_scaled['col1'].mean()) < 0.1
        assert abs(df_scaled['col1'].std() - 1.0) < 0.1
    
    def test_feature_name_preservation(self):
        """Test that feature names are preserved after transformation."""
        df = pd.DataFrame({
            'feature1': [1, 2, 3],
            'feature2': [4, 5, 6]
        })
        
        original_columns = df.columns.tolist()
        
        # Apply scaling
        scaler = StandardScaler()
        df_scaled = pd.DataFrame(
            scaler.fit_transform(df),
            columns=original_columns
        )
        
        assert df_scaled.columns.tolist() == original_columns
    
    def test_train_test_split(self):
        """Test train/test split."""
        df = pd.DataFrame({
            'feature': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            'label': [0, 0, 0, 0, 1, 1, 1, 1, 1, 1]
        })
        
        # Simple split (80% train, 20% test)
        train_size = int(0.8 * len(df))
        train_df = df.iloc[:train_size]
        test_df = df.iloc[train_size:]
        
        assert len(train_df) == 8
        assert len(test_df) == 2
        assert len(train_df) + len(test_df) == len(df)
    
    def test_data_leakage_prevention(self):
        """Test that data leakage is prevented."""
        # Simulate leakage columns
        df = pd.DataFrame({
            'srcip': ['192.168.1.1', '192.168.1.2'],  # Leakage
            'feature1': [1, 2],
            'feature2': [3, 4],
            'label': [0, 1]
        })
        
        leakage_columns = ['srcip']
        df_clean = df.drop(columns=leakage_columns)
        
        assert 'srcip' not in df_clean.columns
        assert 'feature1' in df_clean.columns
        assert 'label' in df_clean.columns


class TestPreprocessingEdgeCases:
    """Test edge cases in preprocessing."""
    
    def test_empty_dataframe(self):
        """Test preprocessing with empty dataframe."""
        df = pd.DataFrame()
        
        # Should handle empty case gracefully
        assert len(df) == 0
        assert list(df.columns) == []
    
    def test_single_row(self):
        """Test preprocessing with single row."""
        df = pd.DataFrame({'col1': [1]})
        
        # Should handle single row
        assert len(df) == 1
        assert df.loc[0, 'col1'] == 1
    
    def test_all_missing_column(self):
        """Test column with all missing values."""
        df = pd.DataFrame({
            'col1': [np.nan, np.nan, np.nan],
            'col2': [1, 2, 3]
        })
        
        # Fill with 0 for all-missing column
        df_filled = df.fillna(0)
        
        assert df_filled['col1'].sum() == 0
        assert df_filled['col2'].sum() == 6
    
    def test_single_value_column(self):
        """Test column with single unique value."""
        df = pd.DataFrame({
            'col1': [5, 5, 5, 5],
            'col2': [1, 2, 3, 4]
        })
        
        # Scaling single-value column should result in zeros
        scaler = StandardScaler()
        df_scaled = pd.DataFrame(
            scaler.fit_transform(df),
            columns=df.columns
        )
        
        # Single value column becomes all zeros after scaling
        assert all(df_scaled['col1'] == pytest.approx(0, abs=0.1))
    
    def test_mixed_data_types(self):
        """Test dataframe with mixed data types."""
        df = pd.DataFrame({
            'int_col': [1, 2, 3],
            'float_col': [1.0, 2.0, 3.0],
            'str_col': ['a', 'b', 'c'],
            'bool_col': [True, False, True]
        })
        
        # Should handle mixed types
        assert len(df) == 3
        assert df['int_col'].dtype == np.int64
        assert df['float_col'].dtype == np.float64
        assert df['str_col'].dtype == object
        assert df['bool_col'].dtype == bool
    
    def test_very_large_values(self):
        """Test handling of very large values."""
        df = pd.DataFrame({
            'col1': [1e10, 2e10, 3e10]
        })
        
        # Should handle large values
        assert df['col1'].max() == 3e10
        
        # Scaling should still work
        scaler = StandardScaler()
        df_scaled = pd.DataFrame(
            scaler.fit_transform(df),
            columns=df.columns
        )
        
        assert not np.isinf(df_scaled['col1']).any()
    
    def test_negative_values(self):
        """Test handling of negative values."""
        df = pd.DataFrame({
            'col1': [-5, -3, 0, 3, 5]
        })
        
        # Should handle negative values
        assert df['col1'].min() == -5
        assert df['col1'].max() == 5
        
        # Scaling should work
        scaler = StandardScaler()
        df_scaled = pd.DataFrame(
            scaler.fit_transform(df),
            columns=df.columns
        )
        
        assert abs(df_scaled['col1'].mean()) < 0.1


class TestSchemaHandling:
    """Test schema handling in preprocessing."""
    
    def test_column_standardization(self):
        """Test column name standardization."""
        df = pd.DataFrame({
            'Source IP': ['192.168.1.1'],
            'Destination-IP': ['192.168.1.2'],
            'Protocol': ['tcp']
        })
        
        # Standardize column names
        df.columns = [col.lower().replace(' ', '_').replace('-', '_') for col in df.columns]
        
        assert 'source_ip' in df.columns
        assert 'destination_ip' in df.columns
        assert 'protocol' in df.columns
    
    def test_missing_expected_columns(self):
        """Test handling of missing expected columns."""
        df = pd.DataFrame({
            'col1': [1, 2, 3]
            # Missing expected columns
        })
        
        expected_columns = ['col1', 'col2', 'col3']
        missing_columns = set(expected_columns) - set(df.columns)
        
        assert len(missing_columns) == 2
        assert 'col2' in missing_columns
        assert 'col3' in missing_columns
    
    def test_extra_columns(self):
        """Test handling of extra unexpected columns."""
        df = pd.DataFrame({
            'col1': [1, 2, 3],
            'extra_col': ['a', 'b', 'c']
        })
        
        expected_columns = ['col1']
        extra_columns = set(df.columns) - set(expected_columns)
        
        assert len(extra_columns) == 1
        assert 'extra_col' in extra_columns


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
