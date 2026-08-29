"""Risk scoring engine for security alerts."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any, Union
import logging

from ..utils.logger import get_logger
from ..utils.config import config
from ..utils.helpers import (
    calculate_risk_score, determine_severity, normalize_score,
    safe_float, validate_threshold
)

logger = get_logger(__name__)


class RiskScoringEngine:
    """Calculate risk scores for security alerts based on multiple factors."""
    
    def __init__(self):
        """Initialize the risk scoring engine."""
        self.weights = config.normalize_risk_weights()
        self.severity_thresholds = config.risk_weights.get('severity_thresholds', {})
        self.anomaly_threshold = config.get('thresholds.anomaly_threshold', 50)
        
        logger.info("Initialized RiskScoringEngine")
    
    def calculate_alert_risk(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score for a single alert."""
        # Extract risk components
        components = self._extract_risk_components(alert_data)
        
        # Calculate weighted risk score
        risk_score = calculate_risk_score(components, self.weights)
        
        # Determine severity
        severity = determine_severity(risk_score, self.severity_thresholds)
        
        # Build result
        result = {
            'risk_score': risk_score,
            'severity': severity,
            'components': components,
            'weights': self.weights,
            'risk_breakdown': self._generate_risk_breakdown(components, self.weights)
        }
        
        return result
    
    def _extract_risk_components(self, alert_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract risk components from alert data."""
        components = {}
        
        # Model confidence
        model_confidence = alert_data.get('confidence', alert_data.get('model_confidence', 0.5))
        if isinstance(model_confidence, (int, float)) and 0 <= model_confidence <= 1:
            components['model_confidence'] = model_confidence * 100  # Convert to 0-100 scale
        else:
            components['model_confidence'] = 50.0  # Default
        
        # Anomaly score
        anomaly_score = alert_data.get('anomaly_score', 0)
        components['anomaly_score'] = normalize_score(anomaly_score)
        
        # Attack severity
        attack_category = alert_data.get('attack_category', alert_data.get('prediction', 'Normal'))
        attack_severity = config.get_attack_severity(attack_category)
        components['attack_severity'] = attack_severity * 100  # Convert to 0-100 scale
        
        # Asset criticality
        asset_criticality = alert_data.get('asset_criticality', 'unknown')
        asset_severity_map = config.risk_weights.get('asset_criticality', {})
        asset_risk = asset_severity_map.get(asset_criticality, asset_severity_map.get('unknown', 0.3))
        components['asset_criticality'] = asset_risk * 100  # Convert to 0-100 scale
        
        # User privilege risk
        user_privilege = alert_data.get('user_privilege', 'unknown')
        privilege_risk_map = config.risk_weights.get('user_privilege_risk', {})
        privilege_risk = privilege_risk_map.get(user_privilege, privilege_risk_map.get('unknown', 0.3))
        components['user_privilege_risk'] = privilege_risk * 100  # Convert to 0-100 scale
        
        # Alert frequency
        alert_frequency = alert_data.get('alert_frequency', 1)
        # Normalize frequency (assuming reasonable range of 1-100)
        components['alert_frequency'] = normalize_score(min(alert_frequency, 100), 0, 100)
        
        # Threat intelligence reputation
        threat_intel_reputation = alert_data.get('threat_intel_reputation', 50)
        components['threat_intel_reputation'] = normalize_score(threat_intel_reputation)
        
        return components
    
    def _generate_risk_breakdown(self, components: Dict[str, float], weights: Dict[str, float]) -> Dict[str, Any]:
        """Generate a detailed breakdown of risk score components."""
        breakdown = {}
        
        for component, value in components.items():
            weight = weights.get(component, 0.0)
            contribution = (value / 100) * weight  # Normalized contribution
            breakdown[component] = {
                'value': value,
                'weight': weight,
                'contribution': contribution * 100,  # As percentage
                'normalized_value': value / 100
            }
        
        return breakdown
    
    def calculate_batch_risk(self, alerts: pd.DataFrame) -> pd.DataFrame:
        """Calculate risk scores for multiple alerts."""
        logger.info(f"Calculating risk scores for {len(alerts)} alerts")
        
        risk_results = []
        
        for _, alert in alerts.iterrows():
            alert_dict = alert.to_dict()
            risk_result = self.calculate_alert_risk(alert_dict)
            risk_results.append(risk_result)
        
        # Add risk results to dataframe
        risk_df = pd.DataFrame(risk_results)
        result_df = pd.concat([alerts.reset_index(drop=True), risk_df], axis=1)
        
        logger.info("Risk score calculation complete")
        return result_df
    
    def update_weights(self, new_weights: Dict[str, float]) -> bool:
        """Update risk scoring weights."""
        # Validate that weights sum to approximately 1.0
        total = sum(new_weights.values())
        
        if abs(total - 1.0) > 0.01:  # Allow small floating point errors
            logger.warning(f"Weights sum to {total}, normalizing")
            # Normalize weights
            new_weights = {k: v / total for k, v in new_weights.items()}
        
        self.weights = new_weights
        logger.info(f"Updated risk weights: {self.weights}")
        return True
    
    def update_thresholds(self, new_thresholds: Dict[str, int]) -> bool:
        """Update severity thresholds."""
        # Validate thresholds
        for severity, threshold in new_thresholds.items():
            validated = validate_threshold(threshold, 0, 100)
            new_thresholds[severity] = validated
        
        self.severity_thresholds = new_thresholds
        logger.info(f"Updated severity thresholds: {self.severity_thresholds}")
        return True
    
    def get_risk_explanation(self, risk_data: Dict[str, Any]) -> str:
        """Generate a human-readable explanation of the risk score."""
        risk_score = risk_data.get('risk_score', 0)
        severity = risk_data.get('severity', 'Unknown')
        breakdown = risk_data.get('risk_breakdown', {})
        
        # Find top contributing factors
        top_factors = sorted(
            breakdown.items(),
            key=lambda x: x[1]['contribution'],
            reverse=True
        )[:3]
        
        explanation_parts = [
            f"Risk Score: {risk_score:.1f}/100 ({severity} severity)",
            "Top contributing factors:"
        ]
        
        for factor, details in top_factors:
            explanation_parts.append(
                f"  - {factor.replace('_', ' ').title()}: {details['contribution']:.1f}% "
                f"(value: {details['value']:.1f}, weight: {details['weight']:.2f})"
            )
        
        return "\n".join(explanation_parts)


def calculate_risk_for_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate risk score for a single alert (convenience function)."""
    engine = RiskScoringEngine()
    return engine.calculate_alert_risk(alert_data)


def calculate_risk_for_dataframe(alerts: pd.DataFrame) -> pd.DataFrame:
    """Calculate risk scores for a dataframe of alerts (convenience function)."""
    engine = RiskScoringEngine()
    return engine.calculate_batch_risk(alerts)


if __name__ == "__main__":
    # Test risk scoring
    test_alert = {
        'confidence': 0.85,
        'anomaly_score': 72,
        'attack_category': 'Exploits',
        'asset_criticality': 'critical',
        'user_privilege': 'admin',
        'alert_frequency': 15,
        'threat_intel_reputation': 60
    }
    
    engine = RiskScoringEngine()
    risk_result = engine.calculate_alert_risk(test_alert)
    
    print("Risk Analysis Result:")
    print(f"Risk Score: {risk_result['risk_score']:.1f}")
    print(f"Severity: {risk_result['severity']}")
    print(f"Risk Explanation:\n{engine.get_risk_explanation(risk_result)}")
