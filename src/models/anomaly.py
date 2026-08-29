"""Anomaly detection using Isolation Forest."""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import logging
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest

from ..utils.logger import get_logger
from ..utils.paths import get_model_dir
from ..utils.config import config
from ..utils.helpers import normalize_score, safe_float

logger = get_logger(__name__)


class AnomalyDetector:
    """Anomaly detection using Isolation Forest."""
    
    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """Initialize the anomaly detector."""
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.training_metadata = {}
        
        # Get model configuration
        anomaly_config = config.get('models.anomaly', {})
        self.contamination = anomaly_config.get('contamination', contamination)
        self.n_estimators = anomaly_config.get('n_estimators', 100)
        self.max_samples = anomaly_config.get('max_samples', 'auto')
        
        logger.info(f"Initialized AnomalyDetector with contamination={contamination}")
    
    def train(self, X_train: pd.DataFrame, y_train: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Train the anomaly detector."""
        logger.info("Training Isolation Forest anomaly detector")
        
        # If labels are provided, train primarily on normal data
        if y_train is not None:
            # Assume label 0 is normal, 1 is attack
            normal_indices = np.where(y_train == 0)[0]
            if len(normal_indices) > 0:
                X_train = X_train.iloc[normal_indices]
                logger.info(f"Training on {len(normal_indices)} normal samples")
            else:
                logger.warning("No normal samples found, training on all data")
        
        # Initialize Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        # Record training start time
        training_start = datetime.now()
        
        # Train model
        self.model.fit(X_train)
        
        # Record training end time
        training_end = datetime.now()
        training_duration = (training_end - training_start).total_seconds()
        
        # Store training metadata
        self.training_metadata = {
            'model_name': 'Isolation Forest Anomaly Detector',
            'model_type': 'anomaly',
            'training_samples': len(X_train),
            'feature_count': X_train.shape[1],
            'feature_names': X_train.columns.tolist(),
            'training_start': training_start.isoformat(),
            'training_end': training_end.isoformat(),
            'training_duration_seconds': training_duration,
            'contamination': self.contamination,
            'n_estimators': self.n_estimators,
            'max_samples': self.max_samples
        }
        
        logger.info(f"Anomaly detector training complete in {training_duration:.2f} seconds")
        
        return self.training_metadata
    
    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make anomaly predictions."""
        if self.model is None:
            raise ValueError("Anomaly detector has not been trained yet")
        
        logger.info(f"Making anomaly predictions on {len(X)} samples")
        
        # Get raw anomaly scores (-1 for anomaly, 1 for normal)
        raw_predictions = self.model.predict(X)
        
        # Get anomaly scores (lower = more anomalous)
        anomaly_scores = self.model.score_samples(X)
        
        # Convert to 0-100 scale (higher = more anomalous)
        # Isolation Forest returns negative scores, where more negative = more anomalous
        # We'll invert and normalize to 0-100
        normalized_scores = normalize_score(-anomaly_scores, min_val=0, max_val=1)
        
        # Convert predictions to binary (0 = normal, 1 = anomaly)
        binary_predictions = (raw_predictions == -1).astype(int)
        
        return binary_predictions, normalized_scores
    
    def get_anomaly_threshold(self, threshold_percentile: float = 50) -> float:
        """Get the anomaly score threshold."""
        # This would typically be determined from validation data
        # For now, return a default threshold
        return threshold_percentile
    
    def save_model(self, filepath: Optional[Path] = None) -> Path:
        """Save the trained anomaly detector."""
        if self.model is None:
            raise ValueError("Anomaly detector has not been trained yet")
        
        if filepath is None:
            model_dir = get_model_dir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = model_dir / f"anomaly_detector_{timestamp}.joblib"
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Save model and metadata
        save_dict = {
            'model': self.model,
            'metadata': self.training_metadata,
            'model_type': 'anomaly',
            'model_name': 'Isolation Forest Anomaly Detector'
        }
        
        joblib.dump(save_dict, filepath)
        logger.info(f"Anomaly detector saved to {filepath}")
        
        return filepath
    
    @classmethod
    def load_model(cls, filepath: Path) -> Tuple[Any, Dict[str, Any]]:
        """Load a trained anomaly detector."""
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        save_dict = joblib.load(filepath)
        
        model = save_dict['model']
        metadata = save_dict.get('metadata', {})
        
        logger.info(f"Loaded anomaly detector from {filepath}")
        
        return model, metadata


def train_anomaly_detector(X_train: pd.DataFrame,
                          y_train: Optional[np.ndarray] = None,
                          contamination: float = 0.1,
                          save_model: bool = True) -> Tuple[Any, Dict[str, Any]]:
    """Train an anomaly detector."""
    detector = AnomalyDetector(contamination=contamination)
    metadata = detector.train(X_train, y_train)
    
    if save_model:
        detector.save_model()
    
    return detector.model, metadata


if __name__ == "__main__":
    # Test anomaly detection
    from ..data.loader import load_data_for_training
    from ..data.preprocessing import preprocess_pipeline
    
    # Load and preprocess data
    features, labels, info = load_data_for_training("synthetic")
    if labels is not None:
        features_processed, labels_processed, preprocessor = preprocess_pipeline(
            features, "label", save_preprocessor=False
        )
        
        # Train anomaly detector
        model, metadata = train_anomaly_detector(
            features_processed, labels_processed, save_model=False
        )
        
        print(f"Trained anomaly detector: {metadata['model_name']}")
        print(f"Training duration: {metadata['training_duration_seconds']:.2f} seconds")
        
        # Test predictions
        predictions, scores = model.predict(features_processed[:10])
        print(f"Sample predictions: {predictions}")
        print(f"Sample anomaly scores: {scores}")
    else:
        print("No labels found for training")
