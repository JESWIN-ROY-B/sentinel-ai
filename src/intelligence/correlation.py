"""Alert correlation and deduplication engine."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import logging
from collections import defaultdict

from ..utils.logger import get_logger
from ..utils.config import config
from ..utils.helpers import generate_incident_id, safe_float

logger = get_logger(__name__)


class AlertCorrelationEngine:
    """Correlate and deduplicate security alerts into incidents."""
    
    def __init__(self):
        """Initialize the correlation engine."""
        self.time_window_minutes = config.get('correlation.time_window_minutes', 30)
        self.similarity_threshold = config.get('correlation.similarity_threshold', 0.7)
        self.group_by_fields = config.get('correlation.group_by_fields', [])
        
        logger.info("Initialized AlertCorrelationEngine")
    
    def correlate_alerts(self, alerts: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Correlate alerts into incidents."""
        logger.info(f"Correlating {len(alerts)} alerts")
        
        if len(alerts) == 0:
            return alerts, {'incidents_created': 0, 'alerts_deduplicated': 0}
        
        # Make a copy to avoid modifying original
        alerts_copy = alerts.copy()

        # Ensure incident_id column is cast to object dtype so string IDs don't trigger LossySetitemError
        if 'incident_id' in alerts_copy.columns:
            alerts_copy['incident_id'] = alerts_copy['incident_id'].astype('object')
        else:
            alerts_copy['incident_id'] = None
            alerts_copy['incident_id'] = alerts_copy['incident_id'].astype('object')

        # Ensure timestamp is datetime
        if 'timestamp' in alerts_copy.columns:
            alerts_copy['timestamp'] = pd.to_datetime(alerts_copy['timestamp'])
        
        # Sort by timestamp
        alerts_copy = alerts_copy.sort_values('timestamp')
        
        # Group alerts into incidents
        incidents = []
        incident_counter = 0
        alerts_deduplicated = 0
        
        # Process alerts chronologically
        for idx, alert in alerts_copy.iterrows():
            # Check if this alert belongs to an existing incident
            matched_incident = self._find_matching_incident(alert, incidents)
            
            if matched_incident:
                # Add to existing incident
                matched_incident['alerts'].append(alert.to_dict())
                matched_incident['alert_count'] += 1
                matched_incident['last_seen'] = alert['timestamp']
                alerts_deduplicated += 1
            else:
                # Create new incident
                new_incident = self._create_incident(alert, incident_counter)
                incidents.append(new_incident)
                incident_counter += 1
        
        # Update alerts with incident IDs cleanly
        for incident in incidents:
            incident_id = incident['incident_id']
            for alert in incident['alerts']:
                # Match alert by timestamp and source_ip to set incident_id
                mask = (alerts_copy['timestamp'] == alert['timestamp'])
                if 'source_ip' in alert and 'source_ip' in alerts_copy.columns:
                    mask &= (alerts_copy['source_ip'] == alert['source_ip'])
                
                alerts_copy.loc[mask, 'incident_id'] = incident_id

        # Calculate correlation metrics
        correlation_metrics = {
            'total_alerts': len(alerts),
            'incidents_created': len(incidents),
            'alerts_deduplicated': alerts_deduplicated,
            'correlation_reduction': (alerts_deduplicated / len(alerts)) * 100 if len(alerts) > 0 else 0,
            'average_alerts_per_incident': len(alerts) / len(incidents) if len(incidents) > 0 else 0
        }
        
        logger.info(f"Correlation complete: {len(incidents)} incidents created from {len(alerts)} alerts")
        
        return alerts_copy, correlation_metrics
    
    def _find_matching_incident(self, alert: pd.Series, incidents: List[Dict]) -> Optional[Dict]:
        """Find an existing incident that matches the alert."""
        alert_time = alert['timestamp']
        
        for incident in incidents:
            # Check time window
            time_diff = (alert_time - incident['last_seen']).total_seconds() / 60
            if time_diff > self.time_window_minutes:
                continue  # Outside time window
            
            # Check similarity based on grouping fields
            similarity = self._calculate_similarity(alert, incident)
            
            if similarity >= self.similarity_threshold:
                return incident
        
        return None
    
    def _calculate_similarity(self, alert: pd.Series, incident: Dict) -> float:
        """Calculate similarity between alert and incident."""
        similarity_score = 0.0
        total_weight = 0.0
        
        # Weight factors
        weights = {
            'source_ip': 0.3,
            'destination_ip': 0.3,
            'protocol': 0.15,
            'service': 0.1,
            'attack_category': 0.15
        }
        
        # Check source IP
        if 'source_ip' in alert and 'source_ips' in incident:
            if alert['source_ip'] in incident['source_ips']:
                similarity_score += weights['source_ip']
            total_weight += weights['source_ip']
        
        # Check destination IP
        if 'destination_ip' in alert and 'affected_assets' in incident:
            if alert['destination_ip'] in incident['affected_assets']:
                similarity_score += weights['destination_ip']
            total_weight += weights['destination_ip']
        
        # Check protocol
        if 'protocol' in alert and 'protocols' in incident:
            if alert['protocol'] in incident['protocols']:
                similarity_score += weights['protocol']
            total_weight += weights['protocol']
        
        # Check service
        if 'service' in alert and 'services' in incident:
            if alert['service'] in incident['services']:
                similarity_score += weights['service']
            total_weight += weights['service']
        
        # Check attack category
        if 'attack_category' in alert and 'attack_category' in incident:
            if alert['attack_category'] == incident['attack_category']:
                similarity_score += weights['attack_category']
            total_weight += weights['attack_category']
        
        # Normalize similarity score
        if total_weight > 0:
            similarity_score = similarity_score / total_weight
        
        return similarity_score
    
    def _create_incident(self, alert: pd.Series, incident_counter: int) -> Dict:
        """Create a new incident from an alert."""
        incident = {
            'incident_id': generate_incident_id(),
            'title': self._generate_incident_title(alert),
            'first_seen': alert['timestamp'],
            'last_seen': alert['timestamp'],
            'alert_count': 1,
            'alerts': [alert.to_dict()],
            'source_ips': [alert.get('source_ip', '')] if 'source_ip' in alert else [],
            'affected_assets': [alert.get('destination_ip', '')] if 'destination_ip' in alert else [],
            'protocols': [alert.get('protocol', '')] if 'protocol' in alert else [],
            'services': [alert.get('service', '')] if 'service' in alert else [],
            'attack_category': alert.get('attack_category', 'Unknown'),
            'severity': alert.get('severity', 'Medium'),
            'status': 'New',
            'correlation_confidence': 1.0
        }
        
        return incident
    
    def _generate_incident_title(self, alert: pd.Series) -> str:
        """Generate a title for the incident."""
        attack_category = alert.get('attack_category', 'Unknown')
        source_ip = alert.get('source_ip', 'Unknown')
        
        if attack_category != 'Normal':
            return f"{attack_category} Activity from {source_ip}"
        else:
            return f"Suspicious Activity from {source_ip}"
    
    def _flatten_incident(self, incident: Dict) -> Dict:
        """Flatten incident structure for dataframe conversion."""
        return {
            'incident_id': incident['incident_id'],
            'title': incident['title'],
            'first_seen': incident['first_seen'],
            'last_seen': incident['last_seen'],
            'alert_count': incident['alert_count'],
            'source_ips': incident['source_ips'],
            'affected_assets': incident['affected_assets'],
            'protocols': incident['protocols'],
            'services': incident['services'],
            'attack_category': incident['attack_category'],
            'severity': incident['severity'],
            'status': incident['status'],
            'correlation_confidence': incident['correlation_confidence']
        }


def correlate_alerts_to_incidents(alerts: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Correlate alerts to incidents (convenience function)."""
    engine = AlertCorrelationEngine()
    alerts_with_incidents, metrics = engine.correlate_alerts(alerts)
    
    # Extract incidents
    incidents = []
    for incident_id in alerts_with_incidents['incident_id'].unique():
        if pd.notna(incident_id):
            incident_alerts = alerts_with_incidents[alerts_with_incidents['incident_id'] == incident_id]
            if len(incident_alerts) > 0:
                # Create incident summary
                incident = {
                    'incident_id': incident_id,
                    'title': f"Incident {incident_id}",
                    'first_seen': incident_alerts['timestamp'].min(),
                    'last_seen': incident_alerts['timestamp'].max(),
                    'alert_count': len(incident_alerts),
                    'source_ips': incident_alerts['source_ip'].unique().tolist() if 'source_ip' in incident_alerts.columns else [],
                    'affected_assets': incident_alerts['destination_ip'].unique().tolist() if 'destination_ip' in incident_alerts.columns else [],
                    'attack_category': incident_alerts['attack_category'].mode()[0] if ('attack_category' in incident_alerts.columns and len(incident_alerts) > 0) else 'Unknown',
                    'severity': incident_alerts['severity'].mode()[0] if ('severity' in incident_alerts.columns and len(incident_alerts) > 0) else 'Medium'
                }
                incidents.append(incident)
    
    incidents_df = pd.DataFrame(incidents)
    
    return alerts_with_incidents, incidents_df, metrics


if __name__ == "__main__":
    base_time = datetime.now()
    test_alerts = pd.DataFrame([
        {
            'timestamp': base_time,
            'source_ip': '192.168.1.10',
            'destination_ip': '192.168.1.100',
            'protocol': 'tcp',
            'service': 'http',
            'attack_category': 'Reconnaissance',
            'severity': 'Medium',
            'incident_id': ''
        },
        {
            'timestamp': base_time + timedelta(minutes=5),
            'source_ip': '192.168.1.10',
            'destination_ip': '192.168.1.100',
            'protocol': 'tcp',
            'service': 'http',
            'attack_category': 'Reconnaissance',
            'severity': 'Medium',
            'incident_id': ''
        },
        {
            'timestamp': base_time + timedelta(minutes=35),
            'source_ip': '192.168.1.15',
            'destination_ip': '192.168.1.101',
            'protocol': 'udp',
            'service': 'dns',
            'attack_category': 'DoS',
            'severity': 'High',
            'incident_id': ''
        }
    ])
    
    engine = AlertCorrelationEngine()
    correlated_alerts, metrics = engine.correlate_alerts(test_alerts)
    
    print("Correlation Metrics:")
    for key, value in metrics.items():
        print(f"  {key}: {value}")
    
    print("\nCorrelated Alerts:")
    print(correlated_alerts[['timestamp', 'source_ip', 'incident_id']])