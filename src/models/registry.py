"""Model registry for managing trained models and metadata."""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
import json
from datetime import datetime
import joblib

from ..utils.logger import get_logger
from ..utils.paths import get_model_dir
from ..utils.helpers import safe_float

logger = get_logger(__name__)


class ModelRegistry:
    """Registry for managing trained models and their metadata."""
    
    def __init__(self):
        """Initialize the model registry."""
        self.models = {}
        self.metadata = {}
        self.registry_file = get_model_dir() / "model_registry.json"
        self._load_registry()
    
    def _load_registry(self):
        """Load model registry from disk."""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, 'r') as f:
                    registry_data = json.load(f)
                    self.metadata = registry_data.get('metadata', {})
                logger.info(f"Loaded model registry from {self.registry_file}")
            except Exception as e:
                logger.error(f"Failed to load registry: {e}")
                self.metadata = {}
        else:
            self.metadata = {}
    
    def _save_registry(self):
        """Save model registry to disk."""
        try:
            registry_data = {
                'metadata': self.metadata,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.registry_file, 'w') as f:
                json.dump(registry_data, f, indent=2)
            
            logger.info(f"Saved model registry to {self.registry_file}")
        except Exception as e:
            logger.error(f"Failed to save registry: {e}")
    
    def register_model(self,
                      model_id: str,
                      model_type: str,
                      model_path: Path,
                      metadata: Dict[str, Any]) -> bool:
        """Register a model in the registry."""
        try:
            model_info = {
                'model_id': model_id,
                'model_type': model_type,
                'model_path': str(model_path),
                'registered_at': datetime.now().isoformat(),
                'metadata': metadata
            }
            
            self.metadata[model_id] = model_info
            self._save_registry()
            
            logger.info(f"Registered model {model_id} of type {model_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register model {model_id}: {e}")
            return False
    
    def get_model_info(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a registered model."""
        return self.metadata.get(model_id)
    
    def list_models(self, model_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all registered models, optionally filtered by type."""
        models = []
        
        for model_id, model_info in self.metadata.items():
            if model_type is None or model_info.get('model_type') == model_type:
                models.append({
                    'model_id': model_id,
                    'model_type': model_info.get('model_type'),
                    'model_path': model_info.get('model_path'),
                    'registered_at': model_info.get('registered_at'),
                    'metadata': model_info.get('metadata', {})
                })
        
        # Sort by registration date (newest first)
        models.sort(key=lambda x: x['registered_at'], reverse=True)
        
        return models
    
    def get_latest_model(self, model_type: str) -> Optional[Dict[str, Any]]:
        """Get the latest model of a specific type."""
        models = self.list_models(model_type)
        return models[0] if models else None
    
    def deregister_model(self, model_id: str) -> bool:
        """Remove a model from the registry."""
        if model_id in self.metadata:
            del self.metadata[model_id]
            self._save_registry()
            logger.info(f"Deregistered model {model_id}")
            return True
        return False
    
    def get_model_statistics(self) -> Dict[str, Any]:
        """Get statistics about registered models."""
        stats = {
            'total_models': len(self.metadata),
            'by_type': {},
            'last_updated': self.metadata.get('last_updated', 'Never')
        }
        
        for model_info in self.metadata.values():
            model_type = model_info.get('model_type', 'unknown')
            stats['by_type'][model_type] = stats['by_type'].get(model_type, 0) + 1
        
        return stats


def generate_model_id(model_type: str, timestamp: Optional[datetime] = None) -> str:
    """Generate a unique model ID."""
    if timestamp is None:
        timestamp = datetime.now()
    
    timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
    return f"{model_type}_{timestamp_str}"


def auto_register_model(model: Any,
                       model_type: str,
                       metadata: Dict[str, Any],
                       model_path: Optional[Path] = None) -> str:
    """Automatically register a model with generated ID."""
    registry = ModelRegistry()
    
    # Generate model ID
    model_id = generate_model_id(model_type)
    
    # Save model if path not provided
    if model_path is None:
        model_dir = get_model_dir()
        model_path = model_dir / f"{model_id}.joblib"
        
        # Save model
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, model_path)
    
    # Register model
    registry.register_model(model_id, model_type, model_path, metadata)
    
    return model_id


if __name__ == "__main__":
    # Test model registry
    registry = ModelRegistry()
    
    # Register a test model
    test_metadata = {
        'model_name': 'Test Model',
        'accuracy': 0.95,
        'training_samples': 1000
    }
    
    model_id = auto_register_model(
        model=None,  # Would be actual model in practice
        model_type='binary',
        metadata=test_metadata
    )
    
    print(f"Registered model: {model_id}")
    
    # List models
    models = registry.list_models()
    print(f"Total models: {len(models)}")
    
    # Get statistics
    stats = registry.get_model_statistics()
    print(f"Registry statistics: {stats}")
