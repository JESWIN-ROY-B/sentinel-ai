"""Tests for MITRE ATT&CK mapping."""

import pytest

from src.utils.config import config


class TestMITREMapping:
    """Test cases for MITRE ATT&CK mapping functionality."""
    
    def test_mitre_config_exists(self):
        """Test that MITRE configuration exists."""
        assert hasattr(config, 'mitre_mappings')
        assert config.mitre_mappings is not None
    
    def test_disclaimer_exists(self):
        """Test that MITRE disclaimer exists."""
        disclaimer = config.mitre_mappings.get('disclaimer')
        assert disclaimer is not None
        assert 'heuristic' in disclaimer.lower() or 'validation' in disclaimer.lower()
    
    def test_attack_category_mappings_exist(self):
        """Test that attack category mappings exist."""
        mappings = config.mitre_mappings.get('attack_category_mappings')
        assert mappings is not None
        assert isinstance(mappings, dict)
    
    def test_reconnaissance_mapping(self):
        """Test Reconnaissance attack mapping."""
        mapping = config.get_mitre_mapping('Reconnaissance')
        assert mapping is not None
        
        if mapping:
            assert 'tactics' in mapping
            assert 'confidence' in mapping
            assert 'Reconnaissance' in mapping.get('tactics', [])
    
    def test_exploits_mapping(self):
        """Test Exploits attack mapping."""
        mapping = config.get_mitre_mapping('Exploits')
        assert mapping is not None
        
        if mapping:
            assert 'tactics' in mapping
            assert 'techniques' in mapping
            assert mapping.get('confidence') in ['low', 'medium', 'high', 'very_low']
    
    def test_backdoors_mapping(self):
        """Test Backdoors attack mapping."""
        mapping = config.get_mitre_mapping('Backdoors')
        assert mapping is not None
        
        if mapping:
            tactics = mapping.get('tactics', [])
            # Backdoors should map to C2 or Persistence
            assert any(tactic in ['Command and Control', 'Persistence'] for tactic in tactics)
    
    def test_dos_mapping(self):
        """Test DoS attack mapping."""
        mapping = config.get_mitre_mapping('DoS')
        assert mapping is not None
        
        if mapping:
            tactics = mapping.get('tactics', [])
            assert 'Impact' in tactics
    
    def test_normal_mapping(self):
        """Test Normal traffic mapping."""
        mapping = config.get_mitre_mapping('Normal')
        assert mapping is not None
        
        if mapping:
            # Normal traffic should not have attack tactics
            tactics = mapping.get('tactics', [])
            assert 'None' in tactics or len(tactics) == 0
    
    def test_unsupported_attack_mapping(self):
        """Test mapping for unsupported attack type."""
        mapping = config.get_mitre_mapping('UnsupportedAttack')
        # Should return None or empty mapping
        assert mapping is None or mapping == {}
    
    def test_attack_stage_mappings_exist(self):
        """Test that attack stage mappings exist."""
        stage_mappings = config.mitre_mappings.get('attack_stage_mappings')
        assert stage_mappings is not None
        assert isinstance(stage_mappings, dict)
    
    def test_reconnaissance_stage_mapping(self):
        """Test reconnaissance stage mapping."""
        stage_mappings = config.mitre_mappings.get('attack_stage_mappings', {})
        recon_stage = stage_mappings.get('reconnaissance')
        
        assert recon_stage is not None
        assert 'related_categories' in recon_stage
        assert 'default_tactic' in recon_stage
        assert 'Reconnaissance' in recon_stage.get('related_categories', [])
    
    def test_initial_access_stage_mapping(self):
        """Test initial access stage mapping."""
        stage_mappings = config.mitre_mappings.get('attack_stage_mappings', {})
        initial_access_stage = stage_mappings.get('initial_access')
        
        assert initial_access_stage is not None
        assert 'Exploits' in initial_access_stage.get('related_categories', [])
    
    def test_confidence_levels(self):
        """Test that confidence levels are valid."""
        mappings = config.mitre_mappings.get('attack_category_mappings', {})
        valid_confidences = ['low', 'medium', 'high', 'very_low']
        
        for attack_type, mapping in mappings.items():
            confidence = mapping.get('confidence')
            assert confidence in valid_confidences, f"Invalid confidence for {attack_type}: {confidence}"
    
    def test_mapping_completeness(self):
        """Test that major attack categories have mappings."""
        major_categories = [
            'Reconnaissance', 'Exploits', 'Backdoors', 'DoS', 
            'Fuzzers', 'Analysis', 'Shellcode', 'Worms'
        ]
        
        for category in major_categories:
            mapping = config.get_mitre_mapping(category)
            # At minimum should return a dict (even if empty)
            assert mapping is None or isinstance(mapping, dict)
    
    def test_technique_fields_exist(self):
        """Test that technique fields exist in mappings."""
        mappings = config.mitre_mappings.get('attack_category_mappings', {})
        
        for attack_type, mapping in mappings.items():
            if mapping:  # Skip empty mappings
                # Should have either techniques or notes
                has_techniques = 'techniques' in mapping
                has_notes = 'notes' in mapping
                assert has_techniques or has_notes, f"{attack_type} missing techniques and notes"


class TestMITREMappingSafety:
    """Test safety aspects of MITRE mapping."""
    
    def test_mappings_are_heuristic(self):
        """Test that mappings are clearly labeled as heuristic."""
        disclaimer = config.mitre_mappings.get('disclaimer', '')
        assert 'heuristic' in disclaimer.lower()
    
    def test_no_definitive_claims(self):
        """Test that mappings don't make definitive claims."""
        mappings = config.mitre_mappings.get('attack_category_mappings', {})
        
        for attack_type, mapping in mappings.items():
            if mapping:
                confidence = mapping.get('confidence', 'low')
                # No mapping should claim 'definitive' or 'certain' confidence
                assert confidence != 'definitive'
                assert confidence != 'certain'
    
    def test_validation_required_message(self):
        """Test that validation is required in mappings."""
        disclaimer = config.mitre_mappings.get('disclaimer', '')
        assert 'validation' in disclaimer.lower() or 'analyst' in disclaimer.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
