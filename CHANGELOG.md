# Changelog

All notable changes to Sentinel AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-08-29

### Added
- Initial release of Sentinel AI
- Binary intrusion detection with LightGBM/XGBoost/HistGradientBoostingClassifier support
- Multi-class attack classification for UNSW-NB15 categories
- Isolation Forest anomaly detection
- Risk scoring engine with configurable weights
- Alert correlation and deduplication
- Incident generation and management
- Attack timeline visualization
- MITRE ATT&CK heuristic mapping
- Template-based incident summary generation
- Optional threat intelligence enrichment with mock provider
- Comprehensive synthetic data generator
- Complete Streamlit dashboard with 9 pages
- Data preprocessing pipeline with validation
- Model persistence and metadata registry
- Explainability module with SHAP support and fallbacks
- Extensive test coverage for all major components
- Configuration management with YAML files
- Logging and error handling

### Features
- **Network Intrusion Detection**: Binary classification (Normal vs Attack)
- **Multi-class Prediction**: 10 UNSW-NB15 attack categories
- **Anomaly Detection**: Isolation Forest with normalized scores
- **Risk Scoring**: Transparent, configurable 7-factor risk scoring
- **Alert Correlation**: Time-window and similarity-based grouping
- **Incident Management**: Status tracking and analyst workflow
- **Explainability**: SHAP-based explanations with fallbacks
- **MITRE Mapping**: Heuristic tactic and technique suggestions
- **Timeline Generation**: Attack progression visualization
- **Synthetic Demo Mode**: Fully functional offline demonstration

### Security
- Human-in-the-loop design with analyst approval requirements
- No autonomous containment, scanning, or remediation capabilities
- Safe data handling with validation and sanitization
- Secure configuration management
- Privacy-conscious operation with IP masking in demo mode

### Documentation
- Comprehensive README with setup instructions
- Architecture documentation
- Model card documentation
- Dataset card documentation
- Threat model documentation
- Demo script documentation
- Inline code documentation

### Testing
- Unit tests for data preprocessing
- Unit tests for risk scoring
- Unit tests for alert correlation
- Unit tests for MITRE mapping
- Unit tests for incident summaries
- Unit tests for synthetic data generation
- Unit tests for data validation

### Configuration
- Risk weights configuration (config/risk_weights.yaml)
- MITRE mappings configuration (config/mitre_mappings.yaml)
- Application settings (config/settings.yaml)
- Logging configuration (config/logging.yaml)
- Environment variables support (.env.example)

### Data
- Synthetic data generator for demo mode
- Sample CSV files for immediate testing
- UNSW-NB15 dataset adapter
- Extensible adapter architecture for future datasets

### Models
- Binary classifier with automatic model selection
- Multi-class classifier with automatic model selection
- Anomaly detector using Isolation Forest
- Model evaluation with comprehensive metrics
- Model registry for tracking trained models

### Dashboard
- Overview page with key metrics
- Live Alerts page with filtering
- Incidents page with correlation metrics
- Incident Detail page with full analysis
- Explainability page with model explanations
- Attack Timeline page with progression visualization
- Model Performance page with metrics
- Data Management page with upload/generation
- Settings page with configuration options

### Performance
- Efficient data processing with pandas
- Scalable model training with sklearn/XGBoost/LightGBM
- Configurable caching and resource management
- Optimized for local-first deployment

### Quality Assurance
- Comprehensive error handling
- Graceful fallbacks for missing dependencies
- Input validation and sanitization
- Logging and monitoring capabilities
- Clean code architecture with separation of concerns

## [Unreleased]

### Planned
- Real SIEM integration
- Live telemetry ingestion
- Additional dataset adapters (CIC-IDS2017, etc.)
- SOAR integration with approval workflows
- Enhanced entity resolution
- Continuous learning and drift detection
- Role-based access control
- Advanced threat intelligence integrations
- Enterprise deployment options
- Real-time alert streaming
- Mobile-responsive dashboard improvements

## [0.1.0] - Development Phase

### Added
- Project foundation and structure
- Core utility modules
- Configuration management
- Logging infrastructure
- Data loading and preprocessing
- Model training infrastructure
- Basic Streamlit dashboard

### Implemented
- Synthetic data generation
- Basic risk scoring
- Simple alert correlation
- MITRE mapping foundation
- Template-based summaries

### Tested
- Unit tests for core utilities
- Integration tests for data pipeline
- Dashboard functionality tests

### Notes
- Initial development phase
- Foundation for production system
- Proof of concept for AI-assisted SOC analysis
