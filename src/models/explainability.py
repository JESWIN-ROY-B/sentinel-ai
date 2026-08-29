"""Explainability module for model predictions using SHAP and fallback methods."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Union
import logging
import warnings

from ..utils.logger import get_logger
from ..utils.helpers import safe_float, normalize_score

logger = get_logger(__name__)

# Suppress SHAP warnings
warnings.filterwarnings('ignore')


class ModelExplainer:
    """Provide explanations for model predictions."""
    
    def __init__(self, model: Any, feature_names: List[str], model_type: str = "binary"):
        """Initialize the model explainer."""
        self.model = model
        self.feature_names = feature_names
        self.model_type = model_type
        self.explainer = None
        self.explanation_method = "shap"  # Default to SHAP
        self.fallback_enabled = True
        
        logger.info(f"Initialized ModelExplainer for {model_type} model")
    
    def init_shap_explainer(self, X_background: Optional[pd.DataFrame] = None):
        """Initialize SHAP explainer."""
        try:
            import shap
            
            logger.info("Initializing SHAP explainer")
            
            # Use a subset of background data for efficiency
            if X_background is not None and len(X_background) > 100:
                X_background = X_background.sample(n=min(100, len(X_background)), random_state=42)
            
            # Try TreeExplainer for tree-based models
            try:
                self.explainer = shap.TreeExplainer(self.model, X_background)
                logger.info("Using SHAP TreeExplainer")
            except Exception as e:
                logger.warning(f"TreeExplainer failed: {e}, trying generic explainer")
                # Fallback to generic explainer
                self.explainer = shap.Explainer(self.model, X_background)
                logger.info("Using SHAP generic explainer")
            
            self.explanation_method = "shap"
            return True
            
        except ImportError:
            logger.warning("SHAP not installed, falling back to feature importance")
            self.explanation_method = "feature_importance"
            return False
        except Exception as e:
            logger.error(f"SHAP initialization failed: {e}")
            if self.fallback_enabled:
                self.explanation_method = "feature_importance"
                return False
            raise
    
    def explain_prediction(self, 
                         X: pd.DataFrame,
                         instance_index: int = 0,
                         max_features: int = 10) -> Dict[str, Any]:
        """Explain a single prediction."""
        logger.info(f"Explaining prediction for instance {instance_index}")
        
        if self.explanation_method == "shap" and self.explainer is not None:
            return self._explain_with_shap(X, instance_index, max_features)
        else:
            return self._explain_with_fallback(X, instance_index, max_features)
    
    def _explain_with_shap(self, 
                          X: pd.DataFrame,
                          instance_index: int,
                          max_features: int) -> Dict[str, Any]:
        """Explain using SHAP values."""
        try:
            import shap
            
            # Get SHAP values for the instance
            instance = X.iloc[[instance_index]]
            shap_values = self.explainer.shap_values(instance)
            
            # Handle different SHAP value formats
            if isinstance(shap_values, list):
                # For binary classification, take the second element (positive class)
                shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
            
            # Ensure shap_values is 2D
            if len(shap_values.shape) == 1:
                shap_values = shap_values.reshape(1, -1)
            
            # Get feature importance
            feature_importance = np.abs(shap_values[0])
            
            # Get top features
            top_indices = np.argsort(feature_importance)[-max_features:][::-1]
            
            # Create explanation
            explanation = {
                'method': 'shap',
                'top_features': [],
                'feature_contributions': {},
                'baseline_value': float(self.explainer.expected_value[0] if isinstance(self.explainer.expected_value, list) else self.explainer.expected_value),
                'total_contribution': float(np.sum(shap_values[0]))
            }
            
            for idx in top_indices:
                feature_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
                contribution = float(shap_values[0][idx])
                importance = float(feature_importance[idx])
                
                explanation['top_features'].append({
                    'feature': feature_name,
                    'contribution': contribution,
                    'importance': importance,
                    'direction': 'positive' if contribution > 0 else 'negative'
                })
                
                explanation['feature_contributions'][feature_name] = contribution
            
            logger.info(f"SHAP explanation generated with {len(explanation['top_features'])} top features")
            return explanation
            
        except Exception as e:
            logger.error(f"SHAP explanation failed: {e}")
            if self.fallback_enabled:
                return self._explain_with_fallback(X, instance_index, max_features)
            raise
    
    def _explain_with_fallback(self,
                              X: pd.DataFrame,
                              instance_index: int,
                              max_features: int) -> Dict[str, Any]:
        """Explain using fallback feature importance method."""
        logger.info("Using fallback feature importance explanation")
        
        instance = X.iloc[instance_index]
        
        # Use feature importance from model if available
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        else:
            # Fallback: use absolute feature values as proxy
            importances = np.abs(instance.values)
        
        # Get top features
        top_indices = np.argsort(importances)[-max_features:][::-1]
        
        # Create explanation
        explanation = {
            'method': 'feature_importance',
            'top_features': [],
            'feature_contributions': {},
            'baseline_value': 0.0,
            'total_contribution': float(np.sum(importances))
        }
        
        for idx in top_indices:
            feature_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
            importance = float(importances[idx])
            feature_value = float(instance.iloc[idx])
            
            explanation['top_features'].append({
                'feature': feature_name,
                'contribution': importance,
                'importance': importance,
                'feature_value': feature_value,
                'direction': 'positive' if feature_value > 0 else 'negative'
            })
            
            explanation['feature_contributions'][feature_name] = importance
        
        logger.info(f"Fallback explanation generated with {len(explanation['top_features'])} top features")
        return explanation
    
    def explain_batch(self, 
                     X: pd.DataFrame,
                     max_features: int = 10) -> List[Dict[str, Any]]:
        """Explain multiple predictions."""
        logger.info(f"Explaining {len(X)} predictions")
        
        explanations = []
        for i in range(len(X)):
            explanation = self.explain_prediction(X, i, max_features)
            explanations.append(explanation)
        
        return explanations
    
    def get_global_feature_importance(self) -> Dict[str, float]:
        """Get global feature importance."""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        else:
            logger.warning("Model does not have feature_importances_ attribute")
            return {}
        
        importance_dict = {}
        for i, importance in enumerate(importances):
            feature_name = self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}"
            importance_dict[feature_name] = float(importance)
        
        # Sort by importance
        importance_dict = dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
        
        return importance_dict
    
    def generate_plain_language_explanation(self, 
                                          explanation: Dict[str, Any],
                                          prediction: str,
                                          confidence: float) -> str:
        """Generate a plain-language explanation of the prediction."""
        top_features = explanation.get('top_features', [])[:5]  # Top 5 features
        
        if not top_features:
            return f"Model predicts {prediction} with {confidence:.1%} confidence based on overall feature patterns."
        
        # Build explanation
        positive_contributors = [f for f in top_features if f.get('direction') == 'positive']
        negative_contributors = [f for f in top_features if f.get('direction') == 'negative']
        
        explanation_parts = []
        
        if positive_contributors:
            pos_features = ", ".join([f['feature'] for f in positive_contributors[:3]])
            explanation_parts.append(f"elevated {pos_features}")
        
        if negative_contributors:
            neg_features = ", ".join([f['feature'] for f in negative_contributors[:3]])
            explanation_parts.append(f"reduced {neg_features}")
        
        if explanation_parts:
            feature_explanation = " and ".join(explanation_parts)
            plain_explanation = (
                f"Model predicts {prediction} with {confidence:.1%} confidence. "
                f"This prediction is influenced by {feature_explanation}. "
                f"Top contributing features: {', '.join([f['feature'] for f in top_features[:3]])}."
            )
        else:
            plain_explanation = (
                f"Model predicts {prediction} with {confidence:.1%} confidence "
                f"based on the overall pattern of feature values."
            )
        
        # Add disclaimer
        plain_explanation += " Model evidence, not proof of causation. Analyst validation is required."
        
        return plain_explanation
    
    def get_baseline_comparison(self,
                              instance: pd.Series,
                              baseline: pd.Series,
                              important_features: List[str]) -> List[str]:
        """Compare instance to baseline for important features."""
        comparisons = []
        
        for feature in important_features:
            if feature in instance.index and feature in baseline.index:
                current_value = instance[feature]
                baseline_value = baseline[feature]
                
                if pd.notna(current_value) and pd.notna(baseline_value):
                    diff = current_value - baseline_value
                    percent_diff = (diff / baseline_value * 100) if baseline_value != 0 else 0
                    
                    if abs(percent_diff) < 10:
                        comparison = f"{feature}: Normal (within 10% of baseline)"
                    elif percent_diff > 0:
                        comparison = f"{feature}: Elevated (+{percent_diff:.1f}% above baseline)"
                    else:
                        comparison = f"{feature}: Reduced ({percent_diff:.1f}% below baseline)"
                    
                    comparisons.append(comparison)
        
        return comparisons


def create_explainer(model: Any,
                    feature_names: List[str],
                    model_type: str = "binary",
                    X_background: Optional[pd.DataFrame] = None) -> ModelExplainer:
    """Create a model explainer."""
    explainer = ModelExplainer(model, feature_names, model_type)
    explainer.init_shap_explainer(X_background)
    return explainer


if __name__ == "__main__":
    # Test explainability
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.datasets import make_classification
    
    # Generate synthetic data
    X, y = make_classification(n_samples=1000, n_features=10, n_informative=5, random_state=42)
    feature_names = [f"feature_{i}" for i in range(10)]
    X = pd.DataFrame(X, columns=feature_names)
    
    # Train model
    model = RandomForestClassifier(random_state=42)
    model.fit(X, y)
    
    # Create explainer
    explainer = create_explainer(model, feature_names, "binary", X)
    
    # Explain a prediction
    explanation = explainer.explain_prediction(X, instance_index=0)
    print(f"Explanation: {explanation}")
    
    # Generate plain language explanation
    plain_explanation = explainer.generate_plain_language_explanation(
        explanation, "Attack", 0.85
    )
    print(f"Plain language explanation: {plain_explanation}")
