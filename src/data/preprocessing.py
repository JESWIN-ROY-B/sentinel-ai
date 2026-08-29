"""Data preprocessing pipeline for cybersecurity data."""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
import joblib
import logging

from ..utils.logger import get_logger
from ..utils.paths import get_processed_data_dir
from ..utils.config import config
from ..utils.constants import LEAKAGE_COLUMNS, NUMERICAL_FEATURES, CATEGORICAL_FEATURES
from ..utils.helpers import safe_float, safe_int

logger = get_logger(__name__)


class DataPreprocessor:
    """Preprocess cybersecurity data for machine learning."""
    
    def __init__(self, 
                 handle_missing: str = "mean",
                 handle_infinite: str = "replace",
                 encoding_method: str = "label",
                 scaling_method: str = "standard",
                 random_seed: int = 42):
        """Initialize the preprocessor with configuration."""
        self.handle_missing = handle_missing
        self.handle_infinite = handle_infinite
        self.encoding_method = encoding_method
        self.scaling_method = scaling_method
        self.random_seed = random_seed
        
        # Fitted preprocessing objects
        self.scalers = {}
        self.encoders = {}
        self.imputers = {}
        self.feature_names = []
        self.label_encoder = None
        
        logger.info(f"Initialized DataPreprocessor with config: "
                   f"missing={handle_missing}, infinite={handle_infinite}, "
                   f"encoding={encoding_method}, scaling={scaling_method}")
    
    def fit(self, df: pd.DataFrame, label_column: Optional[str] = None) -> 'DataPreprocessor':
        """Fit the preprocessor on training data."""
        logger.info("Fitting preprocessor on training data")
        
        # Separate features and labels
        if label_column and label_column in df.columns:
            features_df = df.drop(columns=[label_column])
            labels = df[label_column]
        else:
            features_df = df.copy()
            labels = None
        
        # Store feature names
        self.feature_names = features_df.columns.tolist()
        
        # Handle infinite values
        features_df = self._handle_infinite_values(features_df)
        
        # Handle missing values
        features_df = self._handle_missing_values(features_df, fit=True)
        
        # Remove leakage columns
        features_df = self._remove_leakage_columns(features_df)
        
        # Encode categorical variables
        features_df = self._encode_categorical(features_df, fit=True)
        
        # Scale numerical variables
        features_df = self._scale_numerical(features_df, fit=True)
        
        # Fit label encoder if labels provided
        if labels is not None:
            self.label_encoder = LabelEncoder()
            self.label_encoder.fit(labels.astype(str))
        
        logger.info("Preprocessor fitting complete")
        return self
    
    def transform(self, df: pd.DataFrame, label_column: Optional[str] = None) -> Tuple[pd.DataFrame, Optional[np.ndarray]]:
        """Transform data using fitted preprocessor."""
        logger.info("Transforming data")
        
        # Separate features and labels
        if label_column and label_column in df.columns:
            features_df = df.drop(columns=[label_column])
            labels = df[label_column]
        else:
            features_df = df.copy()
            labels = None
        
        # Handle infinite values
        features_df = self._handle_infinite_values(features_df)
        
        # Handle missing values
        features_df = self._handle_missing_values(features_df, fit=False)
        
        # Remove leakage columns
        features_df = self._remove_leakage_columns(features_df)
        
        # Encode categorical variables
        features_df = self._encode_categorical(features_df, fit=False)
        
        # Scale numerical variables
        features_df = self._scale_numerical(features_df, fit=False)
        
        # Transform labels if encoder exists
        if labels is not None and self.label_encoder is not None:
            try:
                labels_encoded = self.label_encoder.transform(labels.astype(str))
            except ValueError as e:
                logger.warning(f"Unknown labels encountered: {e}")
                # Handle unknown labels by assigning a default value
                labels_encoded = np.array([self.label_encoder.classes_.tolist().index(str(l)) 
                                         if str(l) in self.label_encoder.classes_ else -1 
                                         for l in labels])
        else:
            labels_encoded = None
        
        logger.info("Data transformation complete")
        return features_df, labels_encoded
    
    def fit_transform(self, df: pd.DataFrame, label_column: Optional[str] = None) -> Tuple[pd.DataFrame, Optional[np.ndarray]]:
        """Fit and transform in one step."""
        return self.fit(df, label_column).transform(df, label_column)
    
    def _handle_infinite_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle infinite values in the dataframe."""
        if self.handle_infinite == "replace":
            # Replace inf with max finite value or 0
            for col in df.select_dtypes(include=[np.number]).columns:
                df[col] = df[col].replace([np.inf, -np.inf], np.nan)
                # Then handle as missing values
            logger.debug("Replaced infinite values with NaN")
        elif self.handle_infinite == "drop":
            # Drop rows with infinite values
            before_count = len(df)
            df = df.replace([np.inf, -np.inf], np.nan).dropna()
            after_count = len(df)
            logger.debug(f"Dropped {before_count - after_count} rows with infinite values")
        
        return df
    
    def _handle_missing_values(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Handle missing values in the dataframe."""
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        categorical_cols = df.select_dtypes(include=['object']).columns
        
        for col in numerical_cols:
            if df[col].isnull().any():
                if self.handle_missing == "mean":
                    if fit:
                        self.imputers[col] = df[col].mean()
                    fill_value = self.imputers.get(col, 0)
                elif self.handle_missing == "median":
                    if fit:
                        self.imputers[col] = df[col].median()
                    fill_value = self.imputers.get(col, 0)
                elif self.handle_missing == "most_frequent":
                    if fit:
                        self.imputers[col] = df[col].mode()[0] if not df[col].mode().empty else 0
                    fill_value = self.imputers.get(col, 0)
                else:  # drop
                    df = df.dropna(subset=[col])
                    continue
                
                df[col] = df[col].fillna(fill_value)
        
        for col in categorical_cols:
            if df[col].isnull().any():
                if fit:
                    self.imputers[col] = "Unknown"
                df[col] = df[col].fillna(self.imputers.get(col, "Unknown"))
        
        return df
    
    def _remove_leakage_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove columns that could cause data leakage."""
        # Check which leakage columns exist
        existing_leakage = [col for col in LEAKAGE_COLUMNS if col in df.columns]
        
        if existing_leakage:
            logger.info(f"Removing leakage columns: {existing_leakage}")
            df = df.drop(columns=existing_leakage)
        
        return df
    
    def _encode_categorical(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Encode categorical variables."""
        categorical_cols = df.select_dtypes(include=['object']).columns
        
        for col in categorical_cols:
            if self.encoding_method == "label":
                if fit:
                    self.encoders[col] = LabelEncoder()
                    # Handle unseen values by fitting on all values plus 'Unknown'
                    all_values = list(df[col].astype(str).unique()) + ['Unknown']
                    self.encoders[col].fit(all_values)
                
                if col in self.encoders:
                    # Convert to string and handle unseen values
                    df[col] = df[col].astype(str)
                    df[col] = df[col].apply(lambda x: x if x in self.encoders[col].classes_ else 'Unknown')
                    df[col] = self.encoders[col].transform(df[col])
            
            elif self.encoding_method == "onehot":
                # One-hot encoding creates new columns
                if fit:
                    dummies = pd.get_dummies(df[col], prefix=col)
                    self.encoders[col] = dummies.columns.tolist()
                    df = pd.concat([df.drop(columns=[col]), dummies], axis=1)
                else:
                    # Use stored columns for consistency
                    if col in self.encoders:
                        dummies = pd.get_dummies(df[col], prefix=col)
                        # Ensure all expected columns exist
                        for expected_col in self.encoders[col]:
                            if expected_col not in dummies.columns:
                                dummies[expected_col] = 0
                        df = pd.concat([df.drop(columns=[col]), dummies[self.encoders[col]]], axis=1)
        
        return df
    
    def _scale_numerical(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Scale numerical variables."""
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        
        if self.scaling_method == "none":
            return df
        
        for col in numerical_cols:
            if fit:
                if self.scaling_method == "standard":
                    self.scalers[col] = StandardScaler()
                elif self.scaling_method == "minmax":
                    self.scalers[col] = MinMaxScaler()
                elif self.scaling_method == "robust":
                    self.scalers[col] = RobustScaler()
                
                # Reshape for sklearn
                values = df[col].values.reshape(-1, 1)
                self.scalers[col].fit(values)
            
            if col in self.scalers:
                values = df[col].values.reshape(-1, 1)
                df[col] = self.scalers[col].transform(values).flatten()
        
        return df
    
    def save(self, filepath: Union[str, Path]):
        """Save the fitted preprocessor."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        save_dict = {
            'handle_missing': self.handle_missing,
            'handle_infinite': self.handle_infinite,
            'encoding_method': self.encoding_method,
            'scaling_method': self.scaling_method,
            'random_seed': self.random_seed,
            'scalers': self.scalers,
            'encoders': self.encoders,
            'imputers': self.imputers,
            'feature_names': self.feature_names,
            'label_encoder': self.label_encoder
        }
        
        joblib.dump(save_dict, filepath)
        logger.info(f"Saved preprocessor to {filepath}")
    
    @classmethod
    def load(cls, filepath: Union[str, Path]) -> 'DataPreprocessor':
        """Load a fitted preprocessor."""
        filepath = Path(filepath)
        
        save_dict = joblib.load(filepath)
        
        preprocessor = cls(
            handle_missing=save_dict['handle_missing'],
            handle_infinite=save_dict['handle_infinite'],
            encoding_method=save_dict['encoding_method'],
            scaling_method=save_dict['scaling_method'],
            random_seed=save_dict['random_seed']
        )
        
        preprocessor.scalers = save_dict['scalers']
        preprocessor.encoders = save_dict['encoders']
        preprocessor.imputers = save_dict['imputers']
        preprocessor.feature_names = save_dict['feature_names']
        preprocessor.label_encoder = save_dict['label_encoder']
        
        logger.info(f"Loaded preprocessor from {filepath}")
        return preprocessor


def split_data(df: pd.DataFrame,
               label_column: Optional[str] = None,
               test_size: float = 0.2,
               validation_size: float = 0.1,
               random_seed: int = 42,
               stratify: bool = True) -> Tuple[pd.DataFrame, pd.DataFrame, Optional[pd.DataFrame]]:
    """Split data into train, validation, and test sets."""
    logger.info(f"Splitting data: test_size={test_size}, validation_size={validation_size}")
    
    if label_column and label_column in df.columns:
        stratify_col = df[label_column] if stratify else None
    else:
        stratify_col = None
    
    # First split: train + validation vs test
    if validation_size > 0:
        # Calculate adjusted test size to account for validation split
        adjusted_test_size = test_size / (1 - validation_size)
        train_val_df, test_df = train_test_split(
            df, 
            test_size=adjusted_test_size, 
            random_state=random_seed,
            stratify=stratify_col
        )
        
        # Second split: train vs validation
        if label_column and label_column in train_val_df.columns:
            stratify_col_train = train_val_df[label_column] if stratify else None
        else:
            stratify_col_train = None
        
        train_df, val_df = train_test_split(
            train_val_df,
            test_size=validation_size,
            random_state=random_seed,
            stratify=stratify_col_train
        )
        
        logger.info(f"Split complete: train={len(train_df)}, val={len(val_df)}, test={len(test_df)}")
        return train_df, val_df, test_df
    else:
        # Simple train/test split
        train_df, test_df = train_test_split(
            df,
            test_size=test_size,
            random_state=random_seed,
            stratify=stratify_col
        )
        
        logger.info(f"Split complete: train={len(train_df)}, test={len(test_df)}")
        return train_df, None, test_df


def preprocess_pipeline(df: pd.DataFrame,
                       label_column: Optional[str] = None,
                       preprocessor: Optional[DataPreprocessor] = None,
                       save_preprocessor: bool = True,
                       preprocessor_path: Optional[Union[str, Path]] = None) -> Tuple[pd.DataFrame, Optional[np.ndarray], DataPreprocessor]:
    """Complete preprocessing pipeline."""
    logger.info("Starting preprocessing pipeline")
    
    # Get configuration
    if preprocessor is None:
        preprocessor = DataPreprocessor(
            handle_missing=config.get('data.handle_missing', 'mean'),
            handle_infinite=config.get('data.handle_infinite', 'replace'),
            encoding_method=config.get('data.encoding_method', 'label'),
            scaling_method=config.get('data.scaling_method', 'standard'),
            random_seed=config.get('data.random_seed', 42)
        )
    
    # Fit and transform
    features_df, labels_encoded = preprocessor.fit_transform(df, label_column)
    
    # Save preprocessor if requested
    if save_preprocessor:
        if preprocessor_path is None:
            preprocessor_path = get_processed_data_dir() / "preprocessor.joblib"
        preprocessor.save(preprocessor_path)
    
    logger.info("Preprocessing pipeline complete")
    return features_df, labels_encoded, preprocessor


if __name__ == "__main__":
    # Test preprocessing
    from .loader import DatasetLoader
    
    loader = DatasetLoader()
    df = loader.load_synthetic_data()
    
    preprocessor = DataPreprocessor()
    features, labels, fitted_preprocessor = preprocess_pipeline(df, label_column="label")
    
    print(f"Preprocessed features shape: {features.shape}")
    print(f"Labels shape: {labels.shape if labels is not None else 'None'}")
