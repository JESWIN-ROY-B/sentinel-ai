"""Tests for risk scoring engine."""

import pytest
import pandas as pd
import numpy as np

from src.utils.config import config
from src.utils.helpers import (
    calculate_risk_score, determine_severity, normalize_score,
    safe_float, validate_threshold
)


class TestRiskScoring:
    """Test cases for risk scoring functionality."""
    
    def test_risk_weight_normalization(self):
        """Test that risk weights normalize correctly."""
        normalized_weights = config.normalize_risk_weights()
        
        # Check that weights sum to 1.0
        total_weight = sum(normalized_weights.values())
        assert abs(total_weight - 1.0) < 0.001
        
        # Check that all weights are positive
        for weight in normalized_weights.values():
            assert weight >= 0
    
    def test_get_risk_weight(self):
        """Test getting individual risk weights."""
        confidence_weight = config.get_risk_weight('model_confidence')
        assert isinstance(confidence_weight, float)
        assert confidence_weight >= 0
    
    def test_get_attack_severity(self):
        """Test getting attack severity values."""
        # Test known attack types
        backdoor_severity = config.get_attack_severity('Backdoors')
        normal_severity = config.get_attack_severity('Normal')
        
        assert backdoor_severity > normal_severity
        assert 0 <= backdoor_severity <= 1
        assert 0 <= normal_severity <= 1
    
    def test_calculate_risk_score_complete(self):
        """Test risk score calculation with complete data."""
        components = {
            'model_confidence': 85.0,
            'anomaly_score': 70.0,
            'attack_severity': 80.0,
            'asset_criticality': 90.0,
            'user_privilege_risk': 60.0,
            'alert_frequency': 40.0,
            'threat_intel_reputation': 50.0
        }
        
        weights = config.normalize_risk_weights()
        score = calculate_risk_score(components, weights)
        
        assert 0 <= score <= 100
        assert isinstance(score, float)
    
    def test_calculate_risk_score_partial(self):
        """Test risk score calculation with partial data."""
        components = {
            'model_confidence': 80.0,
            'anomaly_score': 60.0
        }
        
        weights = {
            'model_confidence': 0.6,
            'anomaly_score': 0.4
        }
        
        score = calculate_risk_score(components, weights)
        assert 0 <= score <= 100
    
    def test_calculate_risk_score_missing(self):
        """Test risk score calculation with missing components."""
        components = {
            'model_confidence': 50.0,
            'nonexistent_component': 30.0
        }
        
        weights = config.normalize_risk_weights()
        score = calculate_risk_score(components, weights)
        
        # Should handle missing components gracefully
        assert 0 <= score <= 100
    
    def test_calculate_risk_score_extreme(self):
        """Test risk score calculation with extreme values."""
        components = {
            'model_confidence': 100.0,
            'anomaly_score': 100.0,
            'attack_severity': 100.0
        }
        
        weights = {
            'model_confidence': 0.5,
            'anomaly_score': 0.3,
            'attack_severity': 0.2
        }
        
        score = calculate_risk_score(components, weights)
        assert score >= 80  # Should be high with extreme values
    
    def test_determine_severity_all_levels(self):
        """Test severity determination for all levels."""
        thresholds = config.risk_weights.get('severity_thresholds', {})
        
        # Test each severity level
        assert determine_severity(95, thresholds) == "Critical"
        assert determine_severity(78, thresholds) == "High"
        assert determine_severity(55, thresholds) == "Medium"
        assert determine_severity(25, thresholds) == "Low"
    
    def test_determine_severity_boundary_conditions(self):
        """Test severity determination at boundary conditions."""
        thresholds = {
            'critical': 85,
            'high': 70,
            'medium': 40,
            'low': 0
        }
        
        # Test exact boundaries
        assert determine_severity(85, thresholds) == "Critical"
        assert determine_severity(70, thresholds) == "High"
        assert determine_severity(40, thresholds) == "Medium"
        assert determine_severity(0, thresholds) == "Low"
    
    def test_normalize_score_various_ranges(self):
        """Test score normalization with various ranges."""
        # Standard 0-100 range
        assert normalize_score(50, 0, 100) == 50.0
        
        # Different range
        assert normalize_score(5, 0, 10) == 50.0
        
        # Out of range (high)
        assert normalize_score(150, 0, 100) == 100.0
        
        # Out of range (low)
        assert normalize_score(-10, 0, 100) == 0.0
    
    def test_validate_threshold(self):
        """Test threshold validation."""
        # Valid thresholds
        assert validate_threshold(50) == 50.0
        assert validate_threshold(0) == 0.0
        assert validate_threshold(100) == 100.0
        
        # Invalid thresholds (should be clamped)
        assert validate_threshold(-10) == 0.0
        assert validate_threshold(150) == 100.0
        
        # Invalid input (should default to 0)
        assert validate_threshold(None) == 0.0
        assert validate_threshold("invalid") == 0.0
    
    def test_safe_float_edge_cases(self):
        """Test safe_float with edge cases."""
        assert safe_float(0) == 0.0
        assert safe_float(-50) == -50.0
        assert safe_float(1e10) == 1e10
        assert safe_float(-1e10) == -1e10


class TestRiskScoringIntegration:
    """Integration tests for risk scoring."""
    
    def test_end_to_end_risk_calculation(self):
        """Test complete risk calculation workflow."""
        # Simulate a security alert
        alert_data = {
            'model_confidence': 0.85,
            'anomaly_score': 72.0,
            'attack_category': 'Exploits',
            'asset_criticality': 'critical',
            'user_privilege_risk': 'admin',
            'alert_frequency': 15,
            'threat_intel_reputation': 60.0
        }
        
        # Convert to risk components
        components = {
            'model_confidence': alert_data['model_confidence'] * 100,
            'anomaly_score': alert_data['anomaly_score'],
            'attack_severity': config.get_attack_severity(alert_data['attack_category']) * 100,
            'asset_criticality': config.risk_weights.get('asset_criticality', {}).get('critical', 0.8) * 100,
            'user_privilege_risk': config.risk_weights.get('user_privilege_risk', {}).get('admin', 1.0) * 100,
            'alert_frequency': min(alert_data['alert_frequency'] * 5, 100),
            'threat_intel_reputation': alert_data['threat_intel_reputation']
        }
        
        weights = config.normalize_risk_weights()
        risk_score = calculate_risk_score(components, weights)
        severity = determine_severity(risk_score, config.risk_weights.get('severity_thresholds', {}))
        
        assert 0 <= risk_score <= 100
        assert severity in ["Critical", "High", "Medium", "Low"]
        
        # Exploits with high confidence should be high severity
        assert severity in ["Critical", "High"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
