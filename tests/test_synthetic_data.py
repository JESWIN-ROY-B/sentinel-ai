"""Tests for synthetic data generation."""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

from src.data.synthetic import SyntheticDataGenerator
from src.utils.helpers import (
    safe_float, safe_int, safe_str, normalize_score,
    calculate_risk_score, determine_severity, generate_incident_id,
    mask_ip, timestamp_to_datetime, format_timedelta
)


class TestSyntheticDataGenerator:
    """Test cases for SyntheticDataGenerator."""
    
    def test_initialization(self):
        """Test that the generator initializes correctly."""
        generator = SyntheticDataGenerator(random_seed=42)
        assert generator.random_seed == 42
        assert len(generator.source_ips) > 0
        assert len(generator.dest_ips) > 0
        assert len(generator.protocols) > 0
        assert len(generator.services) > 0
    
    def test_generate_alerts(self):
        """Test alert generation."""
        generator = SyntheticDataGenerator(random_seed=42)
        alerts = generator.generate_alerts(num_alerts=10)
        
        assert isinstance(alerts, pd.DataFrame)
        assert len(alerts) == 10
        assert 'timestamp' in alerts.columns
        assert 'source_ip' in alerts.columns
        assert 'destination_ip' in alerts.columns
        assert 'attack_category' in alerts.columns
        assert 'label' in alerts.columns
    
    def test_generate_assets(self):
        """Test asset generation."""
        generator = SyntheticDataGenerator(random_seed=42)
        assets = generator.generate_assets(num_assets=5)
        
        assert isinstance(assets, pd.DataFrame)
        assert len(assets) == 5
        assert 'asset_id' in assets.columns
        assert 'ip_address' in assets.columns
        assert 'criticality' in assets.columns
    
    def test_generate_users(self):
        """Test user generation."""
        generator = SyntheticDataGenerator(random_seed=42)
        users = generator.generate_users(num_users=5)
        
        assert isinstance(users, pd.DataFrame)
        assert len(users) == 5
        assert 'user_id' in users.columns
        assert 'username' in users.columns
        assert 'privilege_level' in users.columns
    
    def test_generate_incidents(self):
        """Test incident generation."""
        generator = SyntheticDataGenerator(random_seed=42)
        incidents = generator.generate_incidents(num_incidents=5)
        
        assert isinstance(incidents, pd.DataFrame)
        assert len(incidents) == 5
        assert 'incident_id' in incidents.columns
        assert 'severity' in incidents.columns
        assert 'risk_score' in incidents.columns
    
    def test_attack_chains_generation(self):
        """Test that attack chains are generated."""
        generator = SyntheticDataGenerator(random_seed=42)
        incidents = generator.generate_incidents(num_incidents=10)
        
        # Check that some incidents have multi-stage patterns
        multi_stage = incidents[incidents['mitre_tactic'].str.contains(',', na=False)]
        assert len(multi_stage) > 0


class TestHelperFunctions:
    """Test cases for helper functions."""
    
    def test_safe_float(self):
        """Test safe_float conversion."""
        assert safe_float(42) == 42.0
        assert safe_float("42") == 42.0
        assert safe_float(None) == 0.0
        assert safe_float(np.nan) == 0.0
        assert safe_float(np.inf) == 0.0
        assert safe_float("invalid") == 0.0
    
    def test_safe_int(self):
        """Test safe_int conversion."""
        assert safe_int(42) == 42
        assert safe_int("42") == 42
        assert safe_int(None) == 0
        assert safe_int(np.nan) == 0
        assert safe_int(np.inf) == 0
        assert safe_int("invalid") == 0
    
    def test_safe_str(self):
        """Test safe_str conversion."""
        assert safe_str(42) == "42"
        assert safe_str(None) == ""
        assert safe_str(np.nan) == ""
        assert safe_str("test") == "test"
    
    def test_normalize_score(self):
        """Test score normalization."""
        assert normalize_score(50, 0, 100) == 50.0
        assert normalize_score(0, 0, 100) == 0.0
        assert normalize_score(100, 0, 100) == 100.0
        assert normalize_score(150, 0, 100) == 100.0
        assert normalize_score(-10, 0, 100) == 0.0
    
    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        components = {
            'model_confidence': 80.0,
            'anomaly_score': 60.0,
            'attack_severity': 70.0
        }
        weights = {
            'model_confidence': 0.5,
            'anomaly_score': 0.3,
            'attack_severity': 0.2
        }
        
        score = calculate_risk_score(components, weights)
        assert 0 <= score <= 100
    
    def test_determine_severity(self):
        """Test severity determination."""
        thresholds = {
            'critical': 85,
            'high': 70,
            'medium': 40,
            'low': 0
        }
        
        assert determine_severity(90, thresholds) == "Critical"
        assert determine_severity(75, thresholds) == "High"
        assert determine_severity(50, thresholds) == "Medium"
        assert determine_severity(20, thresholds) == "Low"
    
    def test_generate_incident_id(self):
        """Test incident ID generation."""
        id1 = generate_incident_id()
        id2 = generate_incident_id()
        
        assert id1 != id2
        assert id1.startswith("INC-")
        assert id2.startswith("INC-")
    
    def test_mask_ip(self):
        """Test IP masking."""
        assert mask_ip("192.168.1.100") == "192.***.1.***"
        assert mask_ip(None) == "unknown"
        assert mask_ip("") == "unknown"
    
    def test_timestamp_to_datetime(self):
        """Test timestamp conversion."""
        # Test with datetime
        dt = datetime(2025, 8, 29, 10, 30, 0)
        result = timestamp_to_datetime(dt)
        assert result == dt
        
        # Test with string
        result = timestamp_to_datetime("2025-08-29 10:30:00")
        assert isinstance(result, datetime)
        
        # Test with None
        result = timestamp_to_datetime(None)
        assert isinstance(result, datetime)
    
    def test_format_timedelta(self):
        """Test timedelta formatting."""
        assert format_timedelta(30) == "30.0s"
        assert format_timedelta(90) == "1.5m"
        assert format_timedelta(3600) == "1.0h"
        assert format_timedelta(86400) == "1.0d"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
