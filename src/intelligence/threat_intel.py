"""Threat intelligence enrichment (optional provider abstraction)."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any
import logging
from abc import ABC, abstractmethod

from ..utils.logger import get_logger
from ..utils.config import config

logger = get_logger(__name__)


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""
    
    @abstractmethod
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check reputation of an IP address."""
        pass
    
    @abstractmethod
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check reputation of a domain."""
        pass
    
    @abstractmethod
    def get_indicator_details(self, indicator: str) -> Dict[str, Any]:
        """Get details about a threat indicator."""
        pass


class MockThreatIntelProvider(ThreatIntelProvider):
    """Mock threat intelligence provider for demo mode."""
    
    def __init__(self):
        """Initialize the mock provider."""
        self.mock_database = {
            '203.0.113.10': {
                'reputation': 'malicious',
                'confidence': 0.85,
                'first_seen': '2025-01-15',
                'last_seen': '2025-08-20',
                'associated_malware': ['Emotet', 'TrickBot'],
                'threat_types': ['C2', 'Phishing'],
                'tags': ['botnet', 'financial']
            },
            '198.51.100.20': {
                'reputation': 'suspicious',
                'confidence': 0.65,
                'first_seen': '2025-03-10',
                'last_seen': '2025-08-25',
                'associated_malware': [],
                'threat_types': ['Scanning'],
                'tags': ['reconnaissance']
            },
            '192.0.2.30': {
                'reputation': 'unknown',
                'confidence': 0.3,
                'first_seen': None,
                'last_seen': None,
                'associated_malware': [],
                'threat_types': [],
                'tags': []
            }
        }
        
        logger.info("Initialized MockThreatIntelProvider")
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation from mock database."""
        logger.info(f"Checking IP reputation for {ip_address}")
        
        # Return mock data or default unknown response
        mock_data = self.mock_database.get(ip_address, {
            'reputation': 'unknown',
            'confidence': 0.5,
            'first_seen': None,
            'last_seen': None,
            'associated_malware': [],
            'threat_types': [],
            'tags': []
        })
        
        return {
            'ip_address': ip_address,
            'provider': 'mock',
            **mock_data
        }
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation (mock implementation)."""
        logger.info(f"Checking domain reputation for {domain}")
        
        # Mock response
        return {
            'domain': domain,
            'provider': 'mock',
            'reputation': 'unknown',
            'confidence': 0.5,
            'first_seen': None,
            'last_seen': None,
            'associated_malware': [],
            'threat_types': [],
            'tags': []
        }
    
    def get_indicator_details(self, indicator: str) -> Dict[str, Any]:
        """Get indicator details (mock implementation)."""
        logger.info(f"Getting details for indicator {indicator}")
        
        # Check if it's an IP
        if self._is_valid_ip(indicator):
            return self.check_ip_reputation(indicator)
        
        # Otherwise return generic response
        return {
            'indicator': indicator,
            'provider': 'mock',
            'reputation': 'unknown',
            'confidence': 0.5,
            'details': 'No threat intelligence available'
        }
    
    def _is_valid_ip(self, indicator: str) -> bool:
        """Check if indicator is a valid IP address."""
        parts = indicator.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


class ThreatIntelManager:
    """Manage threat intelligence enrichment."""
    
    def __init__(self):
        """Initialize the threat intelligence manager."""
        self.provider = None
        self.enabled = config.get('threat_intel.enabled', False)
        self.provider_name = config.get('threat_intel.provider', 'mock')
        
        if self.enabled:
            self._initialize_provider()
        else:
            logger.info("Threat intelligence enrichment is disabled")
    
    def _initialize_provider(self):
        """Initialize the configured threat intelligence provider."""
        if self.provider_name == 'mock':
            self.provider = MockThreatIntelProvider()
            logger.info("Using mock threat intelligence provider")
        else:
            logger.warning(f"Provider {self.provider_name} not implemented, using mock")
            self.provider = MockThreatIntelProvider()
    
    def enrich_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single alert with threat intelligence."""
        if not self.enabled or self.provider is None:
            return alert_data
        
        enriched_data = alert_data.copy()
        
        # Check source IP reputation
        source_ip = alert_data.get('source_ip')
        if source_ip:
            try:
                ip_reputation = self.provider.check_ip_reputation(source_ip)
                enriched_data['threat_intel'] = ip_reputation
                
                # Calculate threat intelligence reputation score
                reputation_score = self._calculate_reputation_score(ip_reputation)
                enriched_data['threat_intel_reputation'] = reputation_score
            except Exception as e:
                logger.error(f"Failed to enrich alert with threat intel: {e}")
        
        return enriched_data
    
    def enrich_batch(self, alerts: pd.DataFrame) -> pd.DataFrame:
        """Enrich multiple alerts with threat intelligence."""
        if not self.enabled or self.provider is None:
            return alerts
        
        logger.info(f"Enriching {len(alerts)} alerts with threat intelligence")
        
        enriched_alerts = []
        for _, alert in alerts.iterrows():
            enriched_alert = self.enrich_alert(alert.to_dict())
            enriched_alerts.append(enriched_alert)
        
        return pd.DataFrame(enriched_alerts)
    
    def _calculate_reputation_score(self, reputation_data: Dict[str, Any]) -> float:
        """Calculate a reputation score from threat intelligence data."""
        reputation = reputation_data.get('reputation', 'unknown')
        confidence = reputation_data.get('confidence', 0.5)
        
        # Map reputation to score
        reputation_scores = {
            'malicious': 90.0,
            'suspicious': 60.0,
            'unknown': 30.0,
            'benign': 10.0
        }
        
        base_score = reputation_scores.get(reputation, 30.0)
        
        # Adjust by confidence
        final_score = base_score * confidence
        
        return final_score
    
    def is_enabled(self) -> bool:
        """Check if threat intelligence is enabled."""
        return self.enabled
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about the current provider."""
        return {
            'enabled': self.enabled,
            'provider_name': self.provider_name,
            'provider_type': type(self.provider).__name__ if self.provider else None
        }


def get_threat_intel_manager() -> ThreatIntelManager:
    """Get the threat intelligence manager (convenience function)."""
    return ThreatIntelManager()


if __name__ == "__main__":
    # Test threat intelligence
    manager = ThreatIntelManager()
    
    # Test with a mock alert
    test_alert = {
        'source_ip': '203.0.113.10',
        'destination_ip': '192.168.1.100',
        'attack_category': 'Exploits'
    }
    
    enriched_alert = manager.enrich_alert(test_alert)
    
    print("Original alert:")
    print(test_alert)
    print("\nEnriched alert:")
    print(enriched_alert)
    
    print(f"\nProvider info: {manager.get_provider_info()}")
