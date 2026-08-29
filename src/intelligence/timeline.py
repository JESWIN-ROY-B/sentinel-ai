"""Attack timeline generation for incidents."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

from ..utils.logger import get_logger
from ..utils.helpers import timestamp_to_datetime, format_timedelta

logger = get_logger(__name__)


class AttackTimelineGenerator:
    """Generate attack timelines for security incidents."""
    
    def __init__(self):
        """Initialize the timeline generator."""
        logger.info("Initialized AttackTimelineGenerator")
    
    def generate_timeline(self, alerts: pd.DataFrame, incident_id: str) -> Dict[str, Any]:
        """Generate an attack timeline from correlated alerts."""
        logger.info(f"Generating timeline for incident {incident_id}")
        
        if len(alerts) == 0:
            return {
                'incident_id': incident_id,
                'events': [],
                'timeline_summary': 'No events found'
            }
        
        # Ensure timestamp is datetime
        if 'timestamp' in alerts.columns:
            alerts['timestamp'] = pd.to_datetime(alerts['timestamp'])
        
        # Sort by timestamp
        alerts_sorted = alerts.sort_values('timestamp')
        
        # Generate timeline events
        events = []
        for idx, alert in alerts_sorted.iterrows():
            event = self._create_timeline_event(alert, idx)
            events.append(event)
        
        # Calculate timeline statistics
        first_event = events[0] if events else None
        last_event = events[-1] if events else None
        
        timeline = {
            'incident_id': incident_id,
            'events': events,
            'event_count': len(events),
            'first_seen': first_event['timestamp'] if first_event else None,
            'last_seen': last_event['timestamp'] if last_event else None,
            'duration': self._calculate_duration(first_event, last_event) if first_event and last_event else None,
            'timeline_summary': self._generate_timeline_summary(events)
        }
        
        logger.info(f"Generated timeline with {len(events)} events")
        return timeline
    
    def _create_timeline_event(self, alert: pd.Series, event_index: int) -> Dict[str, Any]:
        """Create a timeline event from an alert."""
        timestamp = alert.get('timestamp', datetime.now())
        if not isinstance(timestamp, datetime):
            timestamp = timestamp_to_datetime(timestamp)
        
        event = {
            'event_id': f"event_{event_index}",
            'timestamp': timestamp,
            'event_type': alert.get('attack_category', 'Unknown'),
            'severity': alert.get('severity', 'Medium'),
            'source_ip': alert.get('source_ip', 'Unknown'),
            'destination_ip': alert.get('destination_ip', 'Unknown'),
            'protocol': alert.get('protocol', 'Unknown'),
            'service': alert.get('service', 'Unknown'),
            'description': self._generate_event_description(alert),
            'observed': True,  # All events from alerts are observed
            'mitre_tactic': self._infer_mitre_tactic(alert)
        }
        
        return event
    
    def _generate_event_description(self, alert: pd.Series) -> str:
        """Generate a description for the timeline event."""
        attack_category = alert.get('attack_category', 'Unknown')
        source_ip = alert.get('source_ip', 'Unknown')
        destination_ip = alert.get('destination_ip', 'Unknown')
        protocol = alert.get('protocol', 'Unknown')
        service = alert.get('service', 'Unknown')
        
        if attack_category == 'Normal':
            return f"Normal network traffic from {source_ip} to {destination_ip} using {protocol}/{service}"
        else:
            return f"{attack_category} activity detected from {source_ip} to {destination_ip} using {protocol}/{service}"
    
    def _infer_mitre_tactic(self, alert: pd.Series) -> Optional[str]:
        """Infer MITRE tactic from alert data."""
        attack_category = alert.get('attack_category', 'Unknown')
        
        # Simple heuristic mapping
        tactic_mapping = {
            'Reconnaissance': 'Reconnaissance',
            'Exploits': 'Initial Access',
            'Backdoors': 'Command and Control',
            'DoS': 'Impact',
            'Fuzzers': 'Reconnaissance',
            'Analysis': 'Reconnaissance',
            'Shellcode': 'Execution',
            'Worms': 'Lateral Movement'
        }
        
        return tactic_mapping.get(attack_category)
    
    def _calculate_duration(self, first_event: Dict, last_event: Dict) -> str:
        """Calculate the duration of the timeline."""
        if not first_event or not last_event:
            return "Unknown"
        
        duration = last_event['timestamp'] - first_event['timestamp']
        return format_timedelta(duration.total_seconds())
    
    def _generate_timeline_summary(self, events: List[Dict]) -> str:
        """Generate a summary of the timeline."""
        if not events:
            return "No events to summarize"
        
        # Count attack categories
        attack_counts = {}
        for event in events:
            category = event['event_type']
            attack_counts[category] = attack_counts.get(category, 0) + 1
        
        # Build summary
        summary_parts = []
        for category, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            summary_parts.append(f"{count} {category} events")
        
        return f"Timeline contains {len(events)} events: {', '.join(summary_parts)}"
    
    def generate_attack_progression(self, timeline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate suggested attack progression from timeline."""
        events = timeline.get('events', [])
        if not events:
            return []
        
        progression = []
        seen_stages = set()
        
        for event in events:
            mitre_tactic = event.get('mitre_tactic')
            if mitre_tactic and mitre_tactic not in seen_stages:
                progression.append({
                    'stage': mitre_tactic,
                    'timestamp': event['timestamp'],
                    'event_type': event['event_type'],
                    'observed': True
                })
                seen_stages.add(mitre_tactic)
        
        # Add inferred stages if gaps exist
        common_progression = [
            'Reconnaissance',
            'Initial Access',
            'Execution',
            'Persistence',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Command and Control',
            'Exfiltration',
            'Impact'
        ]
        
        if progression:
            # Fill in gaps
            current_stage_idx = 0
            for i, stage in enumerate(common_progression):
                if i < len(progression) and progression[i]['stage'] == stage:
                    current_stage_idx = i
                elif i > current_stage_idx and i < len(progression):
                    # Add inferred stage
                    progression.insert(i, {
                        'stage': stage,
                        'timestamp': None,  # Inferred, no specific timestamp
                        'event_type': 'Inferred',
                        'observed': False
                    })
        
        return progression
    
    def format_timeline_for_display(self, timeline: Dict[str, Any]) -> str:
        """Format timeline for display."""
        lines = []
        
        lines.append(f"Incident ID: {timeline['incident_id']}")
        lines.append(f"Event Count: {timeline['event_count']}")
        lines.append(f"Duration: {timeline.get('duration', 'Unknown')}")
        lines.append(f"Summary: {timeline['timeline_summary']}")
        lines.append("")
        lines.append("Timeline Events:")
        
        for event in timeline['events']:
            observed_marker = "✓" if event['observed'] else "?"
            lines.append(
                f"  {observed_marker} {event['timestamp']} - {event['event_type']} "
                f"({event['severity']}) - {event['description']}"
            )
        
        return "\n".join(lines)


def generate_incident_timeline(alerts: pd.DataFrame, incident_id: str) -> Dict[str, Any]:
    """Generate a timeline for an incident (convenience function)."""
    generator = AttackTimelineGenerator()
    return generator.generate_timeline(alerts, incident_id)


if __name__ == "__main__":
    # Test timeline generation
    from datetime import datetime, timedelta
    
    # Create test alerts
    base_time = datetime.now()
    test_alerts = pd.DataFrame([
        {
            'timestamp': base_time,
            'source_ip': '192.168.1.10',
            'destination_ip': '192.168.1.100',
            'protocol': 'tcp',
            'service': 'http',
            'attack_category': 'Reconnaissance',
            'severity': 'Medium'
        },
        {
            'timestamp': base_time + timedelta(minutes=15),
            'source_ip': '192.168.1.10',
            'destination_ip': '192.168.1.100',
            'protocol': 'tcp',
            'service': 'http',
            'attack_category': 'Exploits',
            'severity': 'Critical'
        },
        {
            'timestamp': base_time + timedelta(minutes=30),
            'source_ip': '192.168.1.10',
            'destination_ip': '192.168.1.100',
            'protocol': 'tcp',
            'service': 'ssh',
            'attack_category': 'Backdoors',
            'severity': 'High'
        }
    ])
    
    generator = AttackTimelineGenerator()
    timeline = generator.generate_timeline(test_alerts, "INC-001")
    
    print("Timeline:")
    print(generator.format_timeline_for_display(timeline))
    
    print("\nAttack Progression:")
    progression = generator.generate_attack_progression(timeline)
    for step in progression:
        observed = "observed" if step['observed'] else "inferred"
        print(f"  {step['stage']} ({observed})")
