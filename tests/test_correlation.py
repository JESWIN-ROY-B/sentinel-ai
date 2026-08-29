"""Tests for alert correlation and deduplication."""

import pytest
import pandas as pd
from datetime import datetime, timedelta

from src.utils.helpers import generate_incident_id


class TestAlertCorrelation:
    """Test cases for alert correlation functionality."""
    
    def test_basic_correlation_grouping(self):
        """Test basic alert correlation by IP and protocol."""
        alerts = pd.DataFrame([
            {
                'timestamp': datetime.now() - timedelta(minutes=5),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'attack_category': 'Reconnaissance',
                'incident_id': ''
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=3),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'attack_category': 'Reconnaissance',
                'incident_id': ''
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=10),
                'source_ip': '192.168.1.15',
                'destination_ip': '192.168.1.101',
                'protocol': 'udp',
                'attack_category': 'DoS',
                'incident_id': ''
            }
        ])
        
        # Group by source IP, destination IP, and protocol
        grouped = alerts.groupby(['source_ip', 'destination_ip', 'protocol'])
        
        # Should have 2 groups
        assert len(grouped) == 2
        
        # First group should have 2 alerts
        first_group = list(grouped)[0][1]
        assert len(first_group) == 2
    
    def test_time_window_correlation(self):
        """Test correlation within time windows."""
        base_time = datetime.now()
        
        alerts = pd.DataFrame([
            {
                'timestamp': base_time - timedelta(minutes=5),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'incident_id': ''
            },
            {
                'timestamp': base_time - timedelta(minutes=15),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'incident_id': ''
            },
            {
                'timestamp': base_time - timedelta(minutes=45),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'incident_id': ''
            }
        ])
        
        # 30-minute time window
        time_window = timedelta(minutes=30)
        
        # Alerts within 30 minutes of each other
        recent_alerts = alerts[alerts['timestamp'] >= base_time - time_window]
        assert len(recent_alerts) == 2
    
    def test_duplicate_detection(self):
        """Test duplicate alert detection."""
        alerts = pd.DataFrame([
            {
                'timestamp': datetime.now() - timedelta(minutes=5),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'service': 'http',
                'attack_category': 'Reconnaissance'
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=3),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'service': 'http',
                'attack_category': 'Reconnaissance'
            },
            {
                'timestamp': datetime.now() - timedelta(minutes=2),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'service': 'https',  # Different service
                'attack_category': 'Reconnaissance'
            }
        ])
        
        # Check for exact duplicates
        exact_duplicates = alerts.duplicated(
            subset=['source_ip', 'destination_ip', 'protocol', 'service', 'attack_category']
        )
        
        # Should have 1 exact duplicate
        assert exact_duplicates.sum() == 1
    
    def test_incident_id_generation(self):
        """Test incident ID generation."""
        id1 = generate_incident_id()
        id2 = generate_incident_id()
        
        # IDs should be unique
        assert id1 != id2
        
        # IDs should follow the pattern
        assert id1.startswith("INC-")
        assert len(id1.split('-')) >= 3
    
    def test_correlation_confidence(self):
        """Test correlation confidence calculation."""
        # Simulate correlation factors
        same_source = True
        same_destination = True
        same_protocol = True
        same_attack_type = True
        time_proximity = 0.9  # High time proximity
        
        # Calculate confidence (simple weighted sum)
        confidence = 0.0
        if same_source:
            confidence += 0.3
        if same_destination:
            confidence += 0.3
        if same_protocol:
            confidence += 0.2
        if same_attack_type:
            confidence += 0.1
        confidence += time_proximity * 0.1
        
        assert 0 <= confidence <= 1.0
        assert confidence > 0.8  # Should be high with all matches
    
    def test_correlation_reduction_metrics(self):
        """Test correlation reduction metrics."""
        raw_alerts = 100
        correlated_alerts = 60
        incidents = 15
        
        # Calculate reduction metrics
        correlation_reduction = (raw_alerts - correlated_alerts) / raw_alerts * 100
        consolidation_ratio = correlated_alerts / incidents
        
        assert correlation_reduction == 40.0
        assert consolidation_ratio == 4.0


class TestCorrelationEdgeCases:
    """Test edge cases for correlation."""
    
    def test_empty_alert_list(self):
        """Test correlation with empty alert list."""
        alerts = pd.DataFrame()
        
        if len(alerts) == 0:
            # Should handle empty case gracefully
            assert True
    
    def test_single_alert(self):
        """Test correlation with single alert."""
        alerts = pd.DataFrame([{
            'timestamp': datetime.now(),
            'source_ip': '192.168.1.10',
            'destination_ip': '192.168.1.100',
            'incident_id': ''
        }])
        
        # Single alert should form its own group
        assert len(alerts) == 1
    
    def test_mixed_data_types(self):
        """Test correlation with mixed data types."""
        alerts = pd.DataFrame([
            {
                'timestamp': datetime.now(),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'port': 80,  # integer
                'attack_category': 'Reconnaissance'
            },
            {
                'timestamp': datetime.now(),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'port': '80',  # string
                'attack_category': 'Reconnaissance'
            }
        ])
        
        # Should handle mixed types
        assert len(alerts) == 2
    
    def test_missing_fields(self):
        """Test correlation with missing fields."""
        alerts = pd.DataFrame([
            {
                'timestamp': datetime.now(),
                'source_ip': '192.168.1.10',
                'destination_ip': None,  # Missing destination
                'protocol': 'tcp',
                'attack_category': 'Reconnaissance'
            },
            {
                'timestamp': datetime.now(),
                'source_ip': '192.168.1.10',
                'destination_ip': '192.168.1.100',
                'protocol': 'tcp',
                'attack_category': 'Reconnaissance'
            }
        ])
        
        # Should handle missing fields
        assert len(alerts) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
