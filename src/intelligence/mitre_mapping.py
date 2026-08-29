"""MITRE ATT&CK heuristic mapping for attack categories."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any
import logging

from ..utils.logger import get_logger
from ..utils.config import config

logger = get_logger(__name__)


class MITREMapper:
    """Map attack categories to MITRE ATT&CK tactics and techniques."""
    
    def __init__(self):
        """Initialize the MITRE mapper."""
        self.mappings = config.mitre_mappings
        self.disclaimer = self.mappings.get('disclaimer', '')
        self.attack_category_mappings = self.mappings.get('attack_category_mappings', {})
        self.attack_stage_mappings = self.mappings.get('attack_stage_mappings', {})
        
        logger.info("Initialized MITREMapper")
    
    def get_attack_mapping(self, attack_category: str) -> Optional[Dict[str, Any]]:
        """Get MITRE mapping for a specific attack category."""
        return self.attack_category_mappings.get(attack_category)
    
    def get_tactics(self, attack_category: str) -> List[str]:
        """Get MITRE tactics for an attack category."""
        mapping = self.get_attack_mapping(attack_category)
        if mapping:
            return mapping.get('tactics', [])
        return []
    
    def get_techniques(self, attack_category: str) -> List[str]:
        """Get MITRE techniques for an attack category."""
        mapping = self.get_attack_mapping(attack_category)
        if mapping:
            return mapping.get('techniques', [])
        return []
    
    def get_confidence(self, attack_category: str) -> str:
        """Get confidence level for a mapping."""
        mapping = self.get_attack_mapping(attack_category)
        if mapping:
            return mapping.get('confidence', 'low')
        return 'very_low'
    
    def get_notes(self, attack_category: str) -> str:
        """Get mapping notes."""
        mapping = self.get_attack_mapping(attack_category)
        if mapping:
            return mapping.get('notes', '')
        return ''
    
    def get_stage_mapping(self, attack_stage: str) -> Optional[Dict[str, Any]]:
        """Get mapping for an attack stage."""
        return self.attack_stage_mappings.get(attack_stage)
    
    def map_attack_to_stage(self, attack_category: str) -> Optional[str]:
        """Map an attack category to a likely attack stage."""
        for stage, mapping in self.attack_stage_mappings.items():
            related_categories = mapping.get('related_categories', [])
            if attack_category in related_categories:
                return mapping.get('default_tactic', stage)
        return None
    
    def get_attack_progression(self, attack_categories: List[str]) -> List[Dict[str, Any]]:
        """Suggest possible attack progression based on attack categories."""
        progression = []
        
        for category in attack_categories:
            stage = self.map_attack_to_stage(category)
            if stage:
                tactics = self.get_tactics(category)
                techniques = self.get_techniques(category)
                confidence = self.get_confidence(category)
                
                progression.append({
                    'attack_category': category,
                    'stage': stage,
                    'tactics': tactics,
                    'techniques': techniques,
                    'confidence': confidence,
                    'observed': True
                })
        
        return progression
    
    def generate_mitre_summary(self, attack_category: str) -> Dict[str, Any]:
        """Generate a comprehensive MITRE mapping summary."""
        return {
            'attack_category': attack_category,
            'tactics': self.get_tactics(attack_category),
            'techniques': self.get_techniques(attack_category),
            'confidence': self.get_confidence(attack_category),
            'notes': self.get_notes(attack_category),
            'likely_stage': self.map_attack_to_stage(attack_category),
            'disclaimer': self.disclaimer
        }
    
    def format_mitre_for_display(self, mitre_summary: Dict[str, Any]) -> str:
        """Format MITRE summary for display."""
        lines = []
        
        lines.append(f"Attack Category: {mitre_summary['attack_category']}")
        lines.append(f"MITRE Tactics: {', '.join(mitre_summary['tactics'])}")
        lines.append(f"MITRE Techniques: {', '.join(mitre_summary['techniques'])}")
        lines.append(f"Mapping Confidence: {mitre_summary['confidence']}")
        lines.append(f"Likely Attack Stage: {mitre_summary['likely_stage']}")
        
        if mitre_summary['notes']:
            lines.append(f"Notes: {mitre_summary['notes']}")
        
        lines.append("")
        lines.append(f"DISCLAIMER: {mitre_summary['disclaimer']}")
        
        return "\n".join(lines)


def get_mitre_mapping(attack_category: str) -> Dict[str, Any]:
    """Get MITRE mapping for an attack category (convenience function)."""
    mapper = MITREMapper()
    return mapper.generate_mitre_summary(attack_category)


def map_attack_categories_to_mitre(attack_categories: List[str]) -> List[Dict[str, Any]]:
    """Map multiple attack categories to MITRE (convenience function)."""
    mapper = MITREMapper()
    return [mapper.generate_mitre_summary(category) for category in attack_categories]


if __name__ == "__main__":
    # Test MITRE mapping
    mapper = MITREMapper()
    
    # Test various attack categories
    test_categories = ['Reconnaissance', 'Exploits', 'Backdoors', 'DoS', 'Normal']
    
    for category in test_categories:
        summary = mapper.generate_mitre_summary(category)
        print(f"\n{category}:")
        print(mapper.format_mitre_for_display(summary))
    
    # Test attack progression
    attack_sequence = ['Reconnaissance', 'Exploits', 'Backdoors']
    progression = mapper.get_attack_progression(attack_sequence)
    
    print("\nAttack Progression:")
    for step in progression:
        print(f"  {step['attack_category']} -> {step['stage']} (confidence: {step['confidence']})")
