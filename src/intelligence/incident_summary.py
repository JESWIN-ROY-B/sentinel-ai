"""Incident summary generation with template-based and optional LLM approaches."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from ..utils.logger import get_logger
from ..utils.helpers import format_timedelta, safe_float
from .mitre_mapping import MITREMapper
from .timeline import AttackTimelineGenerator

logger = get_logger(__name__)


class IncidentSummaryGenerator:
    """Generate AI-assisted incident summaries."""
    
    def __init__(self):
        """Initialize the incident summary generator."""
        self.mitre_mapper = MITREMapper()
        self.timeline_generator = AttackTimelineGenerator()
        self.required_disclaimer = "AI-generated summary — analyst verification required."
        
        logger.info("Initialized IncidentSummaryGenerator")
    
    def generate_summary(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive incident summary."""
        logger.info(f"Generating summary for incident {incident_data.get('incident_id', 'Unknown')}")
        
        summary = {
            'incident_id': incident_data.get('incident_id', 'Unknown'),
            'title': incident_data.get('title', 'Untitled Incident'),
            'severity': incident_data.get('severity', 'Unknown'),
            'risk_score': incident_data.get('risk_score', 0),
            'executive_summary': self._generate_executive_summary(incident_data),
            'first_seen': incident_data.get('first_seen'),
            'last_seen': incident_data.get('last_seen'),
            'duration': self._calculate_duration(incident_data),
            'alert_count': incident_data.get('alert_count', 0),
            'affected_entities': self._extract_affected_entities(incident_data),
            'attack_category': incident_data.get('attack_category', 'Unknown'),
            'key_evidence': self._extract_key_evidence(incident_data),
            'anomaly_indicators': self._extract_anomaly_indicators(incident_data),
            'mitre_mapping': self._generate_mitre_section(incident_data),
            'timeline': self._generate_timeline_section(incident_data),
            'recommended_actions': self._generate_recommended_actions(incident_data),
            'possible_containment': self._generate_containment_options(incident_data),
            'confidence': incident_data.get('confidence', 0),
            'limitations': self._generate_limitations(incident_data),
            'disclaimer': self.required_disclaimer
        }
        
        logger.info("Incident summary generated successfully")
        return summary
    
    def _generate_executive_summary(self, incident_data: Dict[str, Any]) -> str:
        """Generate executive summary."""
        severity = incident_data.get('severity', 'Unknown')
        attack_category = incident_data.get('attack_category', 'Unknown')
        alert_count = incident_data.get('alert_count', 0)
        affected_assets = incident_data.get('affected_assets', [])
        source_ips = incident_data.get('source_ips', [])
        
        summary_parts = []
        
        # Opening statement
        summary_parts.append(
            f"This {severity.lower()} severity incident involves {attack_category} activity "
            f"generating {alert_count} alerts."
        )
        
        # Affected entities
        if affected_assets:
            summary_parts.append(
                f"Affected assets include {len(affected_assets)} systems: {', '.join(affected_assets[:3])}"
                + ("..." if len(affected_assets) > 3 else "")
            )
        
        # Source information
        if source_ips:
            summary_parts.append(
                f"Activity originated from {len(source_ips)} source IP(s): {', '.join(source_ips[:2])}"
                + ("..." if len(source_ips) > 2 else "")
            )
        
        # Timeframe
        first_seen = incident_data.get('first_seen')
        last_seen = incident_data.get('last_seen')
        if first_seen and last_seen:
            duration = self._calculate_duration(incident_data)
            summary_parts.append(f"Activity observed over a period of {duration}.")
        
        return " ".join(summary_parts)
    
    def _calculate_duration(self, incident_data: Dict[str, Any]) -> str:
        """Calculate incident duration."""
        first_seen = incident_data.get('first_seen')
        last_seen = incident_data.get('last_seen')
        
        if first_seen and last_seen:
            if isinstance(first_seen, str):
                first_seen = datetime.fromisoformat(first_seen)
            if isinstance(last_seen, str):
                last_seen = datetime.fromisoformat(last_seen)
            
            duration = last_seen - first_seen
            return format_timedelta(duration.total_seconds())
        
        return "Unknown"
    
    def _extract_affected_entities(self, incident_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract affected entities from incident data."""
        return {
            'hosts': incident_data.get('affected_assets', []),
            'source_ips': incident_data.get('source_ips', []),
            'users': incident_data.get('affected_users', []),
            'services': incident_data.get('services', [])
        }
    
    def _extract_key_evidence(self, incident_data: Dict[str, Any]) -> List[str]:
        """Extract key evidence from incident data."""
        evidence = []
        
        attack_category = incident_data.get('attack_category', 'Unknown')
        if attack_category != 'Normal':
            evidence.append(f"Attack category identified as {attack_category}")
        
        alert_count = incident_data.get('alert_count', 0)
        if alert_count > 1:
            evidence.append(f"High alert volume ({alert_count} alerts) indicates coordinated activity")
        
        risk_score = incident_data.get('risk_score', 0)
        if risk_score > 70:
            evidence.append(f"High risk score ({risk_score:.1f}) suggests significant threat")
        
        anomaly_score = incident_data.get('anomaly_score', 0)
        if anomaly_score > 50:
            evidence.append(f"Elevated anomaly score ({anomaly_score:.1f}) indicates unusual behavior")
        
        return evidence
    
    def _extract_anomaly_indicators(self, incident_data: Dict[str, Any]) -> List[str]:
        """Extract anomaly indicators."""
        indicators = []
        
        anomaly_score = incident_data.get('anomaly_score', 0)
        if anomaly_score > 70:
            indicators.append("Very high anomaly score detected")
        elif anomaly_score > 50:
            indicators.append("Elevated anomaly score detected")
        
        # Add other anomaly indicators if available
        if incident_data.get('unusual_protocol'):
            indicators.append("Unusual protocol usage detected")
        if incident_data.get('unusual_port'):
            indicators.append("Unusual port activity detected")
        if incident_data.get('unusual_time'):
            indicators.append("Activity outside normal business hours")
        
        return indicators
    
    def _generate_mitre_section(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate MITRE ATT&CK mapping section."""
        attack_category = incident_data.get('attack_category', 'Unknown')
        
        mitre_summary = self.mitre_mapper.generate_mitre_summary(attack_category)
        
        return {
            'tactics': mitre_summary['tactics'],
            'techniques': mitre_summary['techniques'],
            'confidence': mitre_summary['confidence'],
            'likely_stage': mitre_summary['likely_stage'],
            'disclaimer': mitre_summary['disclaimer']
        }
    
    def _generate_timeline_section(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate timeline section."""
        # This would typically use the timeline generator
        # For now, provide basic timeline info
        return {
            'first_seen': incident_data.get('first_seen'),
            'last_seen': incident_data.get('last_seen'),
            'duration': self._calculate_duration(incident_data),
            'event_count': incident_data.get('alert_count', 0),
            'attack_progression': self._infer_attack_progression(incident_data)
        }
    
    def _infer_attack_progression(self, incident_data: Dict[str, Any]) -> List[str]:
        """Infer possible attack progression."""
        attack_category = incident_data.get('attack_category', 'Unknown')
        
        # Simple heuristic progression
        progressions = {
            'Reconnaissance': ['Reconnaissance'],
            'Exploits': ['Reconnaissance', 'Initial Access', 'Execution'],
            'Backdoors': ['Initial Access', 'Persistence', 'Command and Control'],
            'DoS': ['Execution', 'Impact'],
            'Worms': ['Initial Access', 'Lateral Movement', 'Propagation']
        }
        
        return progressions.get(attack_category, ['Unknown'])
    
    def _generate_recommended_actions(self, incident_data: Dict[str, Any]) -> List[str]:
        """Generate recommended investigation actions."""
        actions = []
        severity = incident_data.get('severity', 'Medium')
        attack_category = incident_data.get('attack_category', 'Unknown')
        
        # General actions
        actions.append("Review affected systems for signs of compromise")
        actions.append("Check authentication logs for suspicious activity")
        actions.append("Isolate affected systems if compromise is confirmed")
        
        # Severity-specific actions
        if severity in ['Critical', 'High']:
            actions.append("Escalate to senior security analysts")
            actions.append("Consider immediate containment measures")
            actions.append("Review recent network traffic for lateral movement")
        
        # Attack-specific actions
        if attack_category == 'Backdoors':
            actions.append("Scan for persistent malware and backdoors")
            actions.append("Review outbound connections for C2 activity")
        elif attack_category == 'Exploits':
            actions.append("Patch identified vulnerabilities")
            actions.append("Review system logs for exploit indicators")
        elif attack_category == 'Reconnaissance':
            actions.append("Block scanning source IPs")
            actions.append("Review perimeter security controls")
        
        return actions
    
    def _generate_containment_options(self, incident_data: Dict[str, Any]) -> List[str]:
        """Generate possible containment options for human consideration."""
        options = []
        
        severity = incident_data.get('severity', 'Medium')
        affected_assets = incident_data.get('affected_assets', [])
        
        if severity in ['Critical', 'High']:
            options.append("Network isolation of affected hosts")
            options.append("Disable affected user accounts")
            options.append("Block malicious IP addresses at firewall")
        
        if affected_assets:
            options.append(f"Isolate specific affected systems: {', '.join(affected_assets[:2])}")
        
        options.append("Implement enhanced monitoring for affected systems")
        options.append("Consider temporary service disruption if critical")
        
        return options
    
    def _generate_limitations(self, incident_data: Dict[str, Any]) -> List[str]:
        """Generate limitations section."""
        limitations = [
            "Analysis based on available network telemetry only",
            "May not capture all attack activities",
            "MITRE ATT&CK mappings are heuristic approximations",
            "Requires human validation of all findings",
            "Risk scores are estimates, not absolute measures"
        ]
        
        # Add data-specific limitations
        if incident_data.get('is_synthetic', False):
            limitations.append("Results based on synthetic data, not real-world performance")
        
        confidence = incident_data.get('confidence', 0)
        if confidence < 0.7:
            limitations.append(f"Low model confidence ({confidence:.1%}) may affect accuracy")
        
        return limitations
    
    def format_summary_for_display(self, summary: Dict[str, Any]) -> str:
        """Format the summary for display."""
        lines = []
        
        lines.append("=" * 60)
        lines.append(f"INCIDENT SUMMARY: {summary['incident_id']}")
        lines.append("=" * 60)
        lines.append("")
        
        lines.append(f"Title: {summary['title']}")
        lines.append(f"Severity: {summary['severity']}")
        lines.append(f"Risk Score: {summary['risk_score']:.1f}/100")
        lines.append("")
        
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(summary['executive_summary'])
        lines.append("")
        
        lines.append(f"Timeline: {summary['first_seen']} to {summary['last_seen']} ({summary['duration']})")
        lines.append(f"Alert Count: {summary['alert_count']}")
        lines.append("")
        
        lines.append("AFFECTED ENTITIES")
        lines.append("-" * 40)
        entities = summary['affected_entities']
        if entities['hosts']:
            lines.append(f"Hosts: {', '.join(entities['hosts'][:5])}")
        if entities['source_ips']:
            lines.append(f"Source IPs: {', '.join(entities['source_ips'][:5])}")
        lines.append("")
        
        lines.append("KEY EVIDENCE")
        lines.append("-" * 40)
        for evidence in summary['key_evidence']:
            lines.append(f"• {evidence}")
        lines.append("")
        
        lines.append("MITRE ATT&CK MAPPING")
        lines.append("-" * 40)
        mitre = summary['mitre_mapping']
        lines.append(f"Tactics: {', '.join(mitre['tactics'])}")
        lines.append(f"Techniques: {', '.join(mitre['techniques'])}")
        lines.append(f"Confidence: {mitre['confidence']}")
        lines.append(f"Disclaimer: {mitre['disclaimer']}")
        lines.append("")
        
        lines.append("RECOMMENDED ACTIONS")
        lines.append("-" * 40)
        for action in summary['recommended_actions']:
            lines.append(f"• {action}")
        lines.append("")
        
        lines.append("POSSIBLE CONTAINMENT OPTIONS")
        lines.append("-" * 40)
        for option in summary['possible_containment']:
            lines.append(f"• {option}")
        lines.append("")
        
        lines.append("LIMITATIONS")
        lines.append("-" * 40)
        for limitation in summary['limitations']:
            lines.append(f"• {limitation}")
        lines.append("")
        
        lines.append(f"CONFIDENCE: {summary['confidence']:.1%}")
        lines.append("")
        lines.append(f"DISCLAIMER: {summary['disclaimer']}")
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)


def generate_incident_summary(incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate an incident summary (convenience function)."""
    generator = IncidentSummaryGenerator()
    return generator.generate_summary(incident_data)


if __name__ == "__main__":
    # Test incident summary generation
    test_incident = {
        'incident_id': 'INC-001',
        'title': 'Exploits Activity Detected',
        'severity': 'Critical',
        'risk_score': 85.0,
        'first_seen': datetime.now() - timedelta(hours=2),
        'last_seen': datetime.now() - timedelta(minutes=30),
        'alert_count': 25,
        'affected_assets': ['192.168.1.100', '192.168.1.101'],
        'source_ips': ['203.0.113.10'],
        'attack_category': 'Exploits',
        'confidence': 0.85,
        'anomaly_score': 72.0,
        'is_synthetic': True
    }
    
    generator = IncidentSummaryGenerator()
    summary = generator.generate_summary(test_incident)
    
    print(generator.format_summary_for_display(summary))
