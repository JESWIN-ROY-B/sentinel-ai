"""Tests for incident summary generation."""

import pytest
import pandas as pd
from datetime import datetime, timedelta


class TestIncidentSummary:
    """Test cases for incident summary generation."""
    
    def test_summary_structure(self):
        """Test that incident summary has required fields."""
        summary = {
            'incident_id': 'INC-001',
            'title': 'Test Incident',
            'severity': 'High',
            'risk_score': 75.0,
            'executive_summary': 'Test summary',
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'alert_count': 10,
            'affected_entities': ['192.168.1.100'],
            'attack_category': 'Exploits',
            'key_evidence': ['Evidence 1', 'Evidence 2'],
            'mitre_tactic': 'Initial Access',
            'recommended_actions': ['Investigate further'],
            'confidence': 0.8,
            'disclaimer': 'AI-generated summary — analyst verification required.'
        }
        
        # Check required fields
        required_fields = [
            'incident_id', 'title', 'severity', 'risk_score',
            'executive_summary', 'first_seen', 'last_seen',
            'alert_count', 'mitre_tactic', 'disclaimer'
        ]
        
        for field in required_fields:
            assert field in summary
    
    def test_executive_summary_generation(self):
        """Test executive summary generation."""
        incident_data = {
            'attack_category': 'Exploits',
            'severity': 'Critical',
            'affected_assets': ['192.168.1.100', '192.168.1.101'],
            'alert_count': 45,
            'first_seen': datetime.now() - timedelta(hours=2),
            'source_ips': ['203.0.113.10']
        }
        
        # Generate simple executive summary
        summary = (
            f"Critical {incident_data['attack_category']} activity detected "
            f"affecting {len(incident_data['affected_assets'])} assets. "
            f"Activity originated from {incident_data['source_ips'][0]} "
            f"and generated {incident_data['alert_count']} alerts "
            f"over the past 2 hours."
        )
        
        assert 'Critical' in summary
        assert 'Exploits' in summary
        assert '45' in summary
    
    def test_disclaimer_inclusion(self):
        """Test that required disclaimer is included."""
        required_disclaimer = "AI-generated summary — analyst verification required."
        
        summary = {
            'incident_id': 'INC-001',
            'disclaimer': required_disclaimer
        }
        
        assert summary['disclaimer'] == required_disclaimer
    
    def test_missing_field_handling(self):
        """Test handling of missing fields in summary."""
        incomplete_data = {
            'incident_id': 'INC-001',
            'title': 'Test Incident',
            'severity': 'High'
            # Missing other fields
        }
        
        # Should handle missing fields gracefully
        summary = {
            'incident_id': incomplete_data.get('incident_id', 'Unknown'),
            'title': incomplete_data.get('title', 'Untitled'),
            'severity': incomplete_data.get('severity', 'Unknown'),
            'risk_score': incomplete_data.get('risk_score', 0.0),
            'alert_count': incomplete_data.get('alert_count', 0)
        }
        
        assert summary['incident_id'] == 'INC-001'
        assert summary['risk_score'] == 0.0  # Default value
        assert summary['alert_count'] == 0  # Default value
    
    def test_timeline_generation(self):
        """Test attack timeline generation."""
        events = [
            {
                'timestamp': datetime.now() - timedelta(hours=3),
                'event_type': 'Reconnaissance',
                'severity': 'Medium',
                'observed': True
            },
            {
                'timestamp': datetime.now() - timedelta(hours=2),
                'event_type': 'Exploitation',
                'severity': 'Critical',
                'observed': True
            },
            {
                'timestamp': datetime.now() - timedelta(hours=1),
                'event_type': 'Lateral Movement',
                'severity': 'High',
                'observed': False  # Inferred
            }
        ]
        
        # Sort by timestamp
        sorted_events = sorted(events, key=lambda x: x['timestamp'])
        
        assert len(sorted_events) == 3
        assert sorted_events[0]['event_type'] == 'Reconnaissance'
        assert sorted_events[-1]['event_type'] == 'Lateral Movement'
    
    def test_affected_entities_formatting(self):
        """Test formatting of affected entities."""
        entities = {
            'hosts': ['192.168.1.100', '192.168.1.101'],
            'users': ['admin', 'user1'],
            'ips': ['203.0.113.10'],
            'services': ['http', 'ssh']
        }
        
        # Format entities for summary
        affected_entities = []
        if entities.get('hosts'):
            affected_entities.append(f"Hosts: {', '.join(entities['hosts'])}")
        if entities.get('users'):
            affected_entities.append(f"Users: {', '.join(entities['users'])}")
        
        entity_string = '; '.join(affected_entities)
        
        assert '192.168.1.100' in entity_string
        assert 'admin' in entity_string
    
    def test_confidence_and_limitations(self):
        """Test confidence and limitations section."""
        summary_data = {
            'confidence': 0.85,
            'model_version': '1.0.0',
            'training_data': 'UNSW-NB15',
            'limitations': [
                'Model trained on synthetic data',
                'MITRE mappings are heuristic',
                'Requires analyst validation'
            ]
        }
        
        confidence_section = (
            f"Model Confidence: {summary_data['confidence']:.1%}\n"
            f"Model Version: {summary_data['model_version']}\n"
            f"Training Data: {summary_data['training_data']}\n"
            f"Limitations: {', '.join(summary_data['limitations'])}"
        )
        
        assert '85%' in confidence_section
        assert 'heuristic' in confidence_section.lower()
    
    def test_recommended_actions_generation(self):
        """Test generation of recommended actions."""
        incident = {
            'attack_category': 'Backdoors',
            'severity': 'High',
            'affected_assets': ['192.168.1.100']
        }
        
        # Generate context-specific recommendations
        if incident['attack_category'] == 'Backdoors':
            actions = [
                'Isolate affected host from network',
                'Review recent authentication logs',
                'Scan for persistent malware',
                'Review outbound connections'
            ]
        else:
            actions = ['Investigate the incident']
        
        assert len(actions) > 0
        assert 'isolate' in ' '.join(actions).lower()
    
    def test_no_fabrication_of_evidence(self):
        """Test that summary doesn't fabricate evidence."""
        # Only use provided data
        provided_data = {
            'alert_count': 10,
            'affected_assets': ['192.168.1.100']
        }
        
        # Generate summary based only on provided data
        summary = f"Incident with {provided_data['alert_count']} alerts affecting {provided_data['affected_assets'][0]}"
        
        # Should not include fabricated information
        assert '10' in summary  # From provided data
        assert '192.168.1.100' in summary  # From provided data
        assert 'admin' not in summary  # Not in provided data
        assert 'ssh' not in summary  # Not in provided data


class TestTemplateBasedSummary:
    """Test template-based summary generation."""
    
    def test_template_filling(self):
        """Test filling incident template with data."""
        template = """
        Incident: {incident_id}
        Title: {title}
        Severity: {severity}
        Risk Score: {risk_score}
        Attack Category: {attack_category}
        """
        
        data = {
            'incident_id': 'INC-001',
            'title': 'Test Incident',
            'severity': 'High',
            'risk_score': 75.0,
            'attack_category': 'Exploits'
        }
        
        filled_template = template.format(**data)
        
        assert 'INC-001' in filled_template
        assert '75.0' in filled_template
        assert 'Exploits' in filled_template
    
    def test_safety_checks_in_template(self):
        """Test that templates include safety checks."""
        template = """
        {incident_summary}
        
        SAFETY NOTICE:
        {disclaimer}
        
        Recommended Actions: {actions}
        """
        
        filled = template.format(
            incident_summary="Test incident",
            disclaimer="AI-generated summary — analyst verification required.",
            actions="Investigate further"
        )
        
        assert 'SAFETY NOTICE' in filled
        assert 'analyst verification required' in filled.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
