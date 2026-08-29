"""Model training for binary and multi-class classification."""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import logging
import joblib
from datetime import datetime

from ..utils.logger import get_logger
from ..utils.paths import get_model_dir, get_metrics_dir, get_figures_dir
from ..utils.config import config
from ..utils.helpers import safe_float

logger = get_logger(__name__)


class ModelTrainer:
    """Train machine learning models for intrusion detection."""
    
    def __init__(self, model_type: str = "binary"):
        """Initialize the model trainer."""
        self.model_type = model_type
        self.model = None
        self.model_name = ""
        self.training_metadata = {}
        
        # Get model configuration
        self.model_config = config.get(f'models.{model_type}', {})
        
        logger.info(f"Initialized ModelTrainer for {model_type} classification")
    
    def get_model(self):
        """Get the appropriate model based on availability and configuration."""
        model_preference = self.model_config.get('model_type', 'auto')
        
        if model_preference == "auto":
            # Try LightGBM first, then XGBoost, then fallback
            try:
                import lightgbm as lgb
                logger.info("Using LightGBM model")
                return self._get_lightgbm_model()
            except ImportError:
                logger.warning("LightGBM not available, trying XGBoost")
                try:
                    import xgboost as xgb
                    logger.info("Using XGBoost model")
                    return self._get_xgboost_model()
                except ImportError:
                    logger.warning("XGBoost not available, using HistGradientBoostingClassifier")
                    return self._get_histgradient_model()
        
        elif model_preference == "lightgbm":
            try:
                import lightgbm as lgb
                logger.info("Using LightGBM model (specified)")
                return self._get_lightgbm_model()
            except ImportError:
                logger.error("LightGBM specified but not available")
                raise ImportError("LightGBM is not installed")
        
        elif model_preference == "xgboost":
            try:
                import xgboost as xgb
                logger.info("Using XGBoost model (specified)")
                return self._get_xgboost_model()
            except ImportError:
                logger.error("XGBoost specified but not available")
                raise ImportError("XGBoost is not installed")
        
        else:
            logger.info("Using HistGradientBoostingClassifier (fallback)")
            return self._get_histgradient_model()
    
    def _get_lightgbm_model(self):
        """Get LightGBM model."""
        import lightgbm as lgb
        
        if self.model_type == "binary":
            self.model_name = "LightGBM Binary Classifier"
            model = lgb.LGBMClassifier(
                n_estimators=self.model_config.get('n_estimators', 100),
                max_depth=self.model_config.get('max_depth', 6),
                learning_rate=self.model_config.get('learning_rate', 0.1),
                class_weight=self.model_config.get('class_weight', 'balanced'),
                random_state=config.get('data.random_seed', 42),
                verbose=-1
            )
        else:  # multiclass
            self.model_name = "LightGBM Multi-class Classifier"
            model = lgb.LGBMClassifier(
                n_estimators=self.model_config.get('n_estimators', 100),
                max_depth=self.model_config.get('max_depth', 6),
                learning_rate=self.model_config.get('learning_rate', 0.1),
                class_weight=self.model_config.get('class_weight', 'balanced'),
                random_state=config.get('data.random_seed', 42),
                verbose=-1
            )
        
        return model
    
    def _get_xgboost_model(self):
        """Get XGBoost model."""
        import xgboost as xgb
        
        if self.model_type == "binary":
            self.model_name = "XGBoost Binary Classifier"
            model = xgb.XGBClassifier(
                n_estimators=self.model_config.get('n_estimators', 100),
                max_depth=self.model_config.get('max_depth', 6),
                learning_rate=self.model_config.get('learning_rate', 0.1),
                scale_pos_weight=self.model_config.get('class_weight', 'balanced') == 'balanced',
                random_state=config.get('data.random_seed', 42),
                use_label_encoder=False,
                eval_metric='logloss'
            )
        else:  # multiclass
            self.model_name = "XGBoost Multi-class Classifier"
            model = xgb.XGBClassifier(
                n_estimators=self.model_config.get('n_estimators', 100),
                max_depth=self.model_config.get('max_depth', 6),
                learning_rate=self.model_config.get('learning_rate', 0.1),
                random_state=config.get('data.random_seed', 42),
                use_label_encoder=False,
                eval_metric='mlogloss'
            )
        
        return model
    
    def _get_histgradient_model(self):
        """Get HistGradientBoostingClassifier model."""
        from sklearn.ensemble import HistGradientBoostingClassifier
        
        if self.model_type == "binary":
            self.model_name = "HistGradientBoosting Binary Classifier"
            model = HistGradientBoostingClassifier(
                max_iter=self.model_config.get('n_estimators', 100),
                max_depth=self.model_config.get('max_depth', 6),
                learning_rate=self.model_config.get('learning_rate', 0.1),
                class_weight=self.model_config.get('class_weight', 'balanced'),
                random_state=config.get('data.random_seed', 42)
            )
        else:  # multiclass
            self.model_name = "HistGradientBoosting Multi-class Classifier"
            model = HistGradientBoostingClassifier(
                max_iter=self.model_config.get('n_estimators', 100),
                max_depth=self.model_config.get('max_depth', 6),
                learning_rate=self.model_config.get('learning_rate', 0.1),
                class_weight=self.model_config.get('class_weight', 'balanced'),
                random_state=config.get('data.random_seed', 42)
            )
        
        return model
    
    def train(self, 
              X_train: pd.DataFrame, 
              y_train: np.ndarray,
              X_val: Optional[pd.DataFrame] = None,
              y_val: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Train the model."""
        logger.info(f"Training {self.model_name}")
        
        # Get model
        self.model = self.get_model()
        
        # Record training start time
        training_start = datetime.now()
        
        # Train model
        if X_val is not None and y_val is not None:
            # Use validation set
            self.model.fit(X_train, y_train)
            # Note: LightGBM and XGBoost support early stopping, but we'll keep it simple
        else:
            self.model.fit(X_train, y_train)
        
        # Record training end time
        training_end = datetime.now()
        training_duration = (training_end - training_start).total_seconds()
        
        # Store training metadata
        self.training_metadata = {
            'model_name': self.model_name,
            'model_type': self.model_type,
            'training_samples': len(X_train),
            'feature_count': X_train.shape[1],
            'feature_names': X_train.columns.tolist(),
            'training_start': training_start.isoformat(),
            'training_end': training_end.isoformat(),
            'training_duration_seconds': training_duration,
            'class_distribution': dict(zip(*np.unique(y_train, return_counts=True))),
            'model_config': self.model_config
        }
        
        logger.info(f"Training complete in {training_duration:.2f} seconds")
        logger.info(f"Training samples: {len(X_train)}, Features: {X_train.shape[1]}")
        
        return self.training_metadata
    
    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions with the trained model."""
        if self.model is None:
            raise ValueError("Model has not been trained yet")
        
        logger.info(f"Making predictions on {len(X)} samples")
        
        # Get predictions
        predictions = self.model.predict(X)
        
        # Get prediction probabilities
        if hasattr(self.model, 'predict_proba'):
            probabilities = self.model.predict_proba(X)
            # For binary classification, get probability of positive class
            if self.model_type == "binary" and probabilities.shape[1] == 2:
                probabilities = probabilities[:, 1]
        else:
            # Fallback if no predict_proba
            probabilities = np.ones(len(X)) * 0.5
        
        return predictions, probabilities
    
    def save_model(self, filepath: Optional[Path] = None) -> Path:
        """Save the trained model."""
        if self.model is None:
            raise ValueError("Model has not been trained yet")
        
        if filepath is None:
            model_dir = get_model_dir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = model_dir / f"{self.model_type}_classifier_{timestamp}.joblib"
        
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Save model and metadata
        save_dict = {
            'model': self.model,
            'metadata': self.training_metadata,
            'model_type': self.model_type,
            'model_name': self.model_name
        }
        
        joblib.dump(save_dict, filepath)
        logger.info(f"Model saved to {filepath}")
        
        return filepath
    
    @classmethod
    def load_model(cls, filepath: Path) -> Tuple[Any, Dict[str, Any]]:
        """Load a trained model."""
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        save_dict = joblib.load(filepath)
        
        model = save_dict['model']
        metadata = save_dict.get('metadata', {})
        model_type = save_dict.get('model_type', 'unknown')
        
        logger.info(f"Loaded {model_type} model from {filepath}")
        
        return model, metadata


def train_binary_classifier(X_train: pd.DataFrame, 
                           y_train: np.ndarray,
                           X_val: Optional[pd.DataFrame] = None,
                           y_val: Optional[np.ndarray] = None,
                           save_model: bool = True) -> Tuple[Any, Dict[str, Any]]:
    """Train a binary classifier."""
    trainer = ModelTrainer(model_type="binary")
    metadata = trainer.train(X_train, y_train, X_val, y_val)
    
    if save_model:
        trainer.save_model()
    
    return trainer.model, metadata


def train_multiclass_classifier(X_train: pd.DataFrame,
                               y_train: np.ndarray,
                               X_val: Optional[pd.DataFrame] = None,
                               y_val: Optional[np.ndarray] = None,
                               save_model: bool = True) -> Tuple[Any, Dict[str, Any]]:
    """Train a multi-class classifier."""
    trainer = ModelTrainer(model_type="multiclass")
    metadata = trainer.train(X_train, y_train, X_val, y_val)
    
    if save_model:
        trainer.save_model()
    
    return trainer.model, metadata


if __name__ == "__main__":
    # Test model training
    from ..data.loader import load_data_for_training
    from ..data.preprocessing import preprocess_pipeline
    
    # Load and preprocess data
    features, labels, info = load_data_for_training("synthetic")
    if labels is not None:
        features_processed, labels_processed, preprocessor = preprocess_pipeline(
            features, "label", save_preprocessor=False
        )
        
        # Train binary classifier
        model, metadata = train_binary_classifier(
            features_processed, labels_processed, save_model=False
        )
        
        print(f"Trained model: {metadata['model_name']}")
        print(f"Training duration: {metadata['training_duration_seconds']:.2f} seconds")
    else:
        print("No labels found for training")
