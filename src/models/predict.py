"""Prediction utilities for trained models."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Union
import logging
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.paths import get_model_dir
from ..utils.helpers import safe_float, normalize_score
from .train import ModelTrainer
from .anomaly import AnomalyDetector

logger = get_logger(__name__)


class ModelPredictor:
    """Make predictions using trained models."""
    
    def __init__(self):
        """Initialize the model predictor."""
        self.binary_model = None
        self.multiclass_model = None
        self.anomaly_detector = None
        self.binary_metadata = {}
        self.multiclass_metadata = {}
        self.anomaly_metadata = {}
        
        # Feature names for validation
        self.binary_feature_names = []
        self.multiclass_feature_names = []
        self.anomaly_feature_names = []
    
    def load_binary_model(self, model_path: Optional[Path] = None):
        """Load a trained binary classifier."""
        if model_path is None:
            # Try to find the latest binary model
            model_dir = get_model_dir()
            binary_models = list(model_dir.glob("binary_classifier_*.joblib"))
            if binary_models:
                model_path = max(binary_models, key=lambda p: p.stat().st_mtime)
            else:
                logger.warning("No binary model found")
                return False
        
        try:
            model, metadata = ModelTrainer.load_model(model_path)
            self.binary_model = model
            self.binary_metadata = metadata
            self.binary_feature_names = metadata.get('feature_names', [])
            logger.info(f"Loaded binary model from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load binary model: {e}")
            return False
    
    def load_multiclass_model(self, model_path: Optional[Path] = None):
        """Load a trained multi-class classifier."""
        if model_path is None:
            # Try to find the latest multiclass model
            model_dir = get_model_dir()
            multiclass_models = list(model_dir.glob("multiclass_classifier_*.joblib"))
            if multiclass_models:
                model_path = max(multiclass_models, key=lambda p: p.stat().st_mtime)
            else:
                logger.warning("No multiclass model found")
                return False
        
        try:
            model, metadata = ModelTrainer.load_model(model_path)
            self.multiclass_model = model
            self.multiclass_metadata = metadata
            self.multiclass_feature_names = metadata.get('feature_names', [])
            logger.info(f"Loaded multiclass model from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load multiclass model: {e}")
            return False
    
    def load_anomaly_detector(self, model_path: Optional[Path] = None):
        """Load a trained anomaly detector."""
        if model_path is None:
            # Try to find the latest anomaly detector
            model_dir = get_model_dir()
            anomaly_models = list(model_dir.glob("anomaly_detector_*.joblib"))
            if anomaly_models:
                model_path = max(anomaly_models, key=lambda p: p.stat().st_mtime)
            else:
                logger.warning("No anomaly detector found")
                return False
        
        try:
            model, metadata = AnomalyDetector.load_model(model_path)
            self.anomaly_detector = model
            self.anomaly_metadata = metadata
            self.anomaly_feature_names = metadata.get('feature_names', [])
            logger.info(f"Loaded anomaly detector from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load anomaly detector: {e}")
            return False
    
    def predict_binary(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make binary predictions (Normal vs Attack)."""
        if self.binary_model is None:
            raise ValueError("Binary model not loaded")
        
        # Validate features
        if not self._validate_features(X, self.binary_feature_names):
            raise ValueError("Feature mismatch between input and model")
        
        logger.info(f"Making binary predictions on {len(X)} samples")
        
        # Make predictions
        predictions, probabilities = self.binary_model.predict(X), np.zeros(len(X))
        
        # Get probabilities if available
        if hasattr(self.binary_model, 'predict_proba'):
            probabilities = self.binary_model.predict_proba(X)[:, 1]
        else:
            # Fallback: use predictions as proxy
            probabilities = predictions.astype(float)
        
        return predictions, probabilities
    
    def predict_multiclass(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make multi-class predictions (attack categories)."""
        if self.multiclass_model is None:
            raise ValueError("Multiclass model not loaded")
        
        # Validate features
        if not self._validate_features(X, self.multiclass_feature_names):
            raise ValueError("Feature mismatch between input and model")
        
        logger.info(f"Making multiclass predictions on {len(X)} samples")
        
        # Make predictions
        predictions = self.multiclass_model.predict(X)
        
        # Get probabilities
        if hasattr(self.multiclass_model, 'predict_proba'):
            probabilities = self.multiclass_model.predict_proba(X)
            max_probabilities = np.max(probabilities, axis=1)
        else:
            # Fallback
            max_probabilities = np.ones(len(X)) * 0.5
        
        return predictions, max_probabilities
    
    def predict_anomaly(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make anomaly predictions."""
        if self.anomaly_detector is None:
            raise ValueError("Anomaly detector not loaded")
        
        # Validate features
        if not self._validate_features(X, self.anomaly_feature_names):
            raise ValueError("Feature mismatch between input and model")
        
        logger.info(f"Making anomaly predictions on {len(X)} samples")
        
        # Make predictions
        predictions, scores = self.anomaly_detector.predict(X)
        
        return predictions, scores
    
    def predict_all(self, X: pd.DataFrame) -> Dict[str, Any]:
        """Make predictions using all available models."""
        results = {
            'binary': None,
            'multiclass': None,
            'anomaly': None,
            'combined_risk': None
        }
        
        # Binary prediction
        if self.binary_model is not None:
            try:
                binary_pred, binary_prob = self.predict_binary(X)
                results['binary'] = {
                    'predictions': binary_pred,
                    'probabilities': binary_prob,
                    'labels': ['Normal' if p == 0 else 'Attack' for p in binary_pred]
                }
            except Exception as e:
                logger.error(f"Binary prediction failed: {e}")
        
        # Multiclass prediction
        if self.multiclass_model is not None:
            try:
                multiclass_pred, multiclass_prob = self.predict_multiclass(X)
                results['multiclass'] = {
                    'predictions': multiclass_pred,
                    'probabilities': multiclass_prob,
                    'labels': multiclass_pred.astype(str)
                }
            except Exception as e:
                logger.error(f"Multiclass prediction failed: {e}")
        
        # Anomaly prediction
        if self.anomaly_detector is not None:
            try:
                anomaly_pred, anomaly_score = self.predict_anomaly(X)
                results['anomaly'] = {
                    'predictions': anomaly_pred,
                    'scores': anomaly_score,
                    'labels': ['Normal' if p == 0 else 'Anomaly' for p in anomaly_pred]
                }
            except Exception as e:
                logger.error(f"Anomaly prediction failed: {e}")
        
        # Combined risk score
        if results['binary'] is not None and results['anomaly'] is not None:
            combined_risk = self._calculate_combined_risk(
                results['binary']['probabilities'],
                results['anomaly']['scores']
            )
            results['combined_risk'] = combined_risk
        
        return results
    
    def _validate_features(self, X: pd.DataFrame, expected_features: List[str]) -> bool:
        """Validate that input features match model expectations."""
        if not expected_features:
            return True  # Skip validation if no expected features
        
        input_features = set(X.columns)
        expected_set = set(expected_features)
        
        missing = expected_set - input_features
        extra = input_features - expected_set
        
        if missing:
            logger.warning(f"Missing features: {missing}")
        
        if extra:
            logger.warning(f"Extra features: {extra}")
        
        # Allow missing features if most are present
        missing_ratio = len(missing) / len(expected_features) if expected_features else 0
        return missing_ratio < 0.5  # Allow up to 50% missing features
    
    def _calculate_combined_risk(self, binary_prob: np.ndarray, anomaly_score: np.ndarray) -> np.ndarray:
        """Calculate combined risk score from binary and anomaly predictions."""
        # Weighted combination
        combined = 0.6 * binary_prob + 0.4 * (anomaly_score / 100)
        return normalize_score(combined, min_val=0, max_val=1)
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        return {
            'binary_model_loaded': self.binary_model is not None,
            'multiclass_model_loaded': self.multiclass_model is not None,
            'anomaly_detector_loaded': self.anomaly_detector is not None,
            'binary_metadata': self.binary_metadata,
            'multiclass_metadata': self.multiclass_metadata,
            'anomaly_metadata': self.anomaly_metadata
        }


def load_predictor() -> ModelPredictor:
    """Load a predictor with all available models."""
    predictor = ModelPredictor()
    
    # Try to load all models
    predictor.load_binary_model()
    predictor.load_multiclass_model()
    predictor.load_anomaly_detector()
    
    return predictor


if __name__ == "__main__":
    # Test prediction
    from ..data.loader import load_data_for_training
    from ..data.preprocessing import preprocess_pipeline
    
    # Load and preprocess data
    features, labels, info = load_data_for_training("synthetic")
    if labels is not None:
        features_processed, labels_processed, preprocessor = preprocess_pipeline(
            features, "label", save_preprocessor=False
        )
        
        # Load predictor
        predictor = load_predictor()
        
        # Make predictions on a sample
        sample = features_processed.head(10)
        results = predictor.predict_all(sample)
        
        print("Prediction results:")
        for model_type, result in results.items():
            if result is not None:
                print(f"{model_type}: {result}")
    else:
        print("No labels found for testing")
