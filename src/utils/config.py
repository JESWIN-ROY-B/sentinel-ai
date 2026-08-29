"""Configuration management for Sentinel AI."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """Central configuration management for Sentinel AI."""
    
    def __init__(self):
        """Initialize configuration from files and environment variables."""
        self.project_root = Path(__file__).parent.parent.parent.parent
        self.config_dir = self.project_root / "config"
        self._load_settings()
        self._load_risk_weights()
        self._load_mitre_mappings()
        self._load_env_variables()
    
    def _load_settings(self):
        """Load main settings from YAML file."""
        settings_path = self.config_dir / "settings.yaml"
        if settings_path.exists():
            with open(settings_path, 'r') as f:
                self.settings = yaml.safe_load(f)
        else:
            self.settings = self._get_default_settings()
    
    def _load_risk_weights(self):
        """Load risk scoring weights from YAML file."""
        risk_weights_path = self.config_dir / "risk_weights.yaml"
        if risk_weights_path.exists():
            with open(risk_weights_path, 'r') as f:
                self.risk_weights = yaml.safe_load(f)
        else:
            self.risk_weights = self._get_default_risk_weights()
    
    def _load_mitre_mappings(self):
        """Load MITRE ATT&CK mappings from YAML file."""
        mitre_path = self.config_dir / "mitre_mappings.yaml"
        if mitre_path.exists():
            with open(mitre_path, 'r') as f:
                self.mitre_mappings = yaml.safe_load(f)
        else:
            self.mitre_mappings = self._get_default_mitre_mappings()
    
    def _load_env_variables(self):
        """Load configuration from environment variables."""
        self.env = {
            'app_name': os.getenv('APP_NAME', 'Sentinel AI'),
            'app_env': os.getenv('APP_ENV', 'development'),
            'log_level': os.getenv('LOG_LEVEL', 'INFO'),
            'debug': os.getenv('DEBUG', 'false').lower() == 'true',
            'llm_provider': os.getenv('LLM_PROVIDER', 'template'),
            'llm_api_key': os.getenv('LLM_API_KEY', ''),
            'threat_intel_provider': os.getenv('THREAT_INTEL_PROVIDER', 'mock'),
            'threat_intel_api_key': os.getenv('THREAT_INTEL_API_KEY', ''),
            'random_seed': int(os.getenv('RANDOM_SEED', '42')),
            'max_file_size_mb': int(os.getenv('MAX_FILE_SIZE_MB', '100')),
            'validate_uploads': os.getenv('VALIDATE_UPLOADS', 'true').lower() == 'true',
            'sanitize_outputs': os.getenv('SANITIZE_OUTPUTS', 'true').lower() == 'true',
            'log_security_events': os.getenv('LOG_SECURITY_EVENTS', 'true').lower() == 'true',
            'synthetic_data_enabled': os.getenv('SYNTHETIC_DATA_ENABLED', 'true').lower() == 'true',
            'mask_ips_in_demo': os.getenv('MASK_IPS_IN_DEMO', 'true').lower() == 'true',
        }
    
    def _get_default_settings(self) -> Dict[str, Any]:
        """Get default settings if config file is missing."""
        return {
            'app': {
                'name': 'Sentinel AI',
                'version': '1.0.0',
                'debug': False,
                'log_level': 'INFO'
            },
            'data': {
                'random_seed': 42,
                'test_size': 0.2,
                'validation_size': 0.1
            },
            'models': {
                'binary': {'model_type': 'auto'},
                'multiclass': {'model_type': 'auto'},
                'anomaly': {'model_type': 'isolation_forest'}
            }
        }
    
    def _get_default_risk_weights(self) -> Dict[str, Any]:
        """Get default risk weights if config file is missing."""
        return {
            'risk_weights': {
                'model_confidence': 0.35,
                'anomaly_score': 0.20,
                'attack_severity': 0.15,
                'asset_criticality': 0.10,
                'user_privilege_risk': 0.10,
                'alert_frequency': 0.05,
                'threat_intel_reputation': 0.05
            },
            'severity_thresholds': {
                'critical': 85,
                'high': 70,
                'medium': 40,
                'low': 0
            }
        }
    
    def _get_default_mitre_mappings(self) -> Dict[str, Any]:
        """Get default MITRE mappings if config file is missing."""
        return {
            'disclaimer': 'MITRE ATT&CK mapping is a heuristic investigation aid and must be validated by a security analyst.',
            'attack_category_mappings': {}
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation."""
        keys = key.split('.')
        value = self.settings
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def get_risk_weight(self, factor: str) -> float:
        """Get a specific risk weight factor."""
        weights = self.risk_weights.get('risk_weights', {})
        return weights.get(factor, 0.0)
    
    def normalize_risk_weights(self) -> Dict[str, float]:
        """Normalize risk weights to sum to 1.0."""
        weights = self.risk_weights.get('risk_weights', {})
        total = sum(weights.values())
        if total == 0:
            return weights
        return {k: v / total for k, v in weights.items()}
    
    def get_attack_severity(self, attack_type: str) -> float:
        """Get severity score for a specific attack type."""
        severity_map = self.risk_weights.get('attack_severity', {})
        return severity_map.get(attack_type, 0.5)
    
    def get_severity_threshold(self, severity: str) -> int:
        """Get threshold value for a severity level."""
        thresholds = self.risk_weights.get('severity_thresholds', {})
        return thresholds.get(severity.lower(), 0)
    
    def get_mitre_mapping(self, attack_category: str) -> Optional[Dict[str, Any]]:
        """Get MITRE ATT&CK mapping for an attack category."""
        mappings = self.mitre_mappings.get('attack_category_mappings', {})
        return mappings.get(attack_category)
    
    def get_path(self, path_type: str) -> Path:
        """Get common project paths."""
        paths = {
            'project_root': self.project_root,
            'config_dir': self.config_dir,
            'data_dir': self.project_root / 'data',
            'raw_data_dir': self.project_root / 'data' / 'raw',
            'processed_data_dir': self.project_root / 'data' / 'processed',
            'sample_data_dir': self.project_root / 'data' / 'sample',
            'model_dir': self.project_root / 'models',
            'artifact_dir': self.project_root / 'artifacts',
            'metrics_dir': self.project_root / 'artifacts' / 'metrics',
            'figures_dir': self.project_root / 'artifacts' / 'figures',
            'logs_dir': self.project_root / 'logs',
        }
        return paths.get(path_type, self.project_root)
    
    def ensure_directories(self):
        """Ensure all required directories exist."""
        directories = [
            self.get_path('data_dir'),
            self.get_path('raw_data_dir'),
            self.get_path('processed_data_dir'),
            self.get_path('sample_data_dir'),
            self.get_path('model_dir'),
            self.get_path('artifact_dir'),
            self.get_path('metrics_dir'),
            self.get_path('figures_dir'),
            self.get_path('logs_dir'),
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)


# Global configuration instance
config = Config()
config.ensure_directories()
