# Model Card: Sentinel AI Intrusion Detection Models

## Model Information

**Model Name**: Sentinel AI Intrusion Detection System  
**Version**: 1.0.0  
**Type**: Ensemble of supervised and unsupervised ML models  
**Release Date**: 2025-08-29  
**License**: MIT License  

## Model Purpose

Sentinel AI uses multiple machine learning models to detect network intrusions, classify attack types, and identify anomalous behavior in network traffic. The system is designed as a human-in-the-loop security assistant to help SOC analysts prioritize and investigate security alerts more efficiently.

### Primary Use Cases

1. **Binary Classification**: Distinguish between normal and malicious network traffic
2. **Multi-class Classification**: Classify attacks into 10 UNSW-NB15 categories
3. **Anomaly Detection**: Identify unusual or novel behavior patterns
4. **Risk Scoring**: Calculate composite risk scores for security alerts
5. **Alert Correlation**: Group related alerts into coherent incidents

## Model Architecture

### Binary Classifier

**Purpose**: Normal vs Attack classification

**Model Options** (automatic selection based on availability):
1. **LightGBM** (preferred): Gradient boosting framework
2. **XGBoost** (alternative): Extreme gradient boosting
3. **HistGradientBoostingClassifier** (fallback): Scikit-learn implementation

**Configuration**:
- Number of estimators: 100
- Max depth: 6
- Learning rate: 0.1
- Class weighting: Balanced
- Random seed: 42

### Multi-class Classifier

**Purpose**: Attack category classification

**Supported Categories**:
- Normal
- Fuzzers
- Analysis
- Backdoors
- DoS
- Exploits
- Generic
- Reconnaissance
- Shellcode
- Worms

**Model Options**: Same as binary classifier

### Anomaly Detector

**Purpose**: Identify unusual behavior patterns

**Algorithm**: Isolation Forest

**Configuration**:
- Number of estimators: 100
- Contamination: 0.1
- Max samples: Auto
- Random state: 42

## Training Data

### Primary Dataset: UNSW-NB15

**Dataset Description**: The UNSW-NB15 dataset was created by the Australian Centre for Cyber Security (ACCS) to provide a comprehensive set of network traffic data for intrusion detection research.

**Dataset Size**: 
- Training set: ~175,000 records
- Testing set: ~83,000 records
- Features: 49 network flow features
- Attack categories: 10 classes

**Data Split**:
- Training: 70% (when no official split provided)
- Validation: 10%
- Testing: 20%

**Preprocessing**:
- Missing value handling: Mean imputation
- Infinite value replacement: Replace with 0
- Categorical encoding: Label encoding
- Numerical scaling: Standard scaling
- Feature selection: Removal of leakage columns

### Synthetic Data

**Purpose**: Demonstration and testing

**Generation**: Realistic synthetic data generator creating:
- 500 network alerts
- 50 assets
- 30 users
- 20 incidents
- Multi-stage attack chains

**Limitations**: Synthetic data is for demonstration only and does not represent real-world performance.

## Model Performance

### Binary Classifier Metrics

**Expected Performance** (on UNSW-NB15):
- Accuracy: ~85-90%
- Precision: ~80-85%
- Recall: ~75-80%
- F1-Score: ~77-82%
- ROC-AUC: ~0.85-0.90

**Note**: These are approximate ranges. Actual performance depends on training data and configuration.

### Multi-class Classifier Metrics

**Expected Performance** (on UNSW-NB15):
- Accuracy: ~75-80%
- Macro F1-Score: ~65-75%
- Weighted F1-Score: ~70-78%

**Per-class Performance**: Varies significantly by attack category:
- High accuracy: Normal, DoS, Exploits
- Medium accuracy: Reconnaissance, Backdoors
- Lower accuracy: Fuzzers, Analysis, Shellcode, Worms

### Anomaly Detector Metrics

**Expected Performance**:
- Accuracy: ~70-80%
- Precision: ~60-70%
- Recall: ~65-75%
- F1-Score: ~62-72%

**Performance Notes**: Anomaly detection performance is highly dependent on the normality of training data and the contamination parameter.

## Model Limitations

### Dataset Bias

1. **Temporal Bias**: Training data may not reflect current threat landscape
2. **Geographic Bias**: Network patterns may vary by region
3. **Environment Bias**: Different network environments have different baseline patterns

### Concept Drift

1. **Attack Evolution**: New attack techniques may not be recognized
2. **Protocol Changes**: New protocols may not be properly classified
3. **Traffic Pattern Changes**: Normal traffic patterns evolve over time

### False Positives

1. **Legitimate Activity**: Normal activities may be flagged as malicious
2. **Unusual but Benign**: Unusual patterns may be legitimate business activities
3. **Context Missing**: Lack of context may lead to incorrect classifications

### False Negatives

1. **Novel Attacks**: New attack types may not be detected
2. **Polymorphic Attacks**: Attack variants may evade detection
3. **Encrypted Traffic**: Encrypted payloads may hide malicious indicators

### General Limitations

1. **Benchmark-to-Production Gap**: Lab performance may not reflect real-world performance
2. **Incomplete Telemetry**: Limited visibility may miss important indicators
3. **Heuristic Correlations**: Alert correlation may group unrelated events
4. **MITRE Mapping**: ATT&CK mappings are heuristic, not definitive

## Ethical Considerations

### Privacy

1. **IP Address Handling**: IPs are masked in demo mode
2. **Data Minimization**: Only necessary data is processed
3. **No Credential Storage**: No credentials or secrets are stored or logged

### Fairness

1. **Geographic Neutrality**: Models are trained to detect attacks regardless of source
2. **No Profiling**: System does not profile based on user characteristics
3. **Equal Treatment**: All network traffic is evaluated using the same criteria

### Transparency

1. **Explainability**: Model predictions are explainable using SHAP or fallback methods
2. **Risk Transparency**: Risk scoring components are clearly displayed
3. **Limitation Disclosure**: All model limitations are clearly documented

### Human Oversight

1. **Analyst Approval**: All response actions require human approval
2. **Evidence-Based**: AI outputs are presented as evidence, not proof
3. **Validation Required**: All findings require analyst validation

## Safety and Security

### Safety Mechanisms

1. **No Autonomous Actions**: System never takes automatic response actions
2. **Human-in-the-Loop**: Analysts remain central to the decision process
3. **Recommendation Only**: System provides recommendations, not decisions
4. **Containment Options**: Containment suggestions require human approval

### Security Measures

1. **Input Validation**: All inputs are validated before processing
2. **Output Sanitization**: All outputs are sanitized to prevent injection
3. **Error Handling**: Graceful error handling prevents information leakage
4. **Audit Logging**: Security events are logged for compliance

### Data Protection

1. **No Data Retention**: No unnecessary data retention
2. **Secure Storage**: Models and data are stored securely
3. **Access Control**: Role-based access control for production deployment
4. **Encryption**: Sensitive data is encrypted at rest

## Model Maintenance

### Retraining Schedule

**Recommended**: Retrain models quarterly or when:
- Significant performance degradation is observed
- New attack patterns emerge
- Network environment changes significantly
- New training data becomes available

### Performance Monitoring

**Key Metrics to Monitor**:
- Accuracy, precision, recall, F1-score
- False positive rate
- False negative rate
- Prediction latency
- Alert reduction rate
- Analyst satisfaction

### Drift Detection

**Indicators of Drift**:
- Decreasing model performance
- Increasing false positive rate
- Changing data distribution
- New attack patterns in false negatives

## Model Versioning

**Versioning Scheme**: Semantic versioning (MAJOR.MINOR.PATCH)

**Version History**:
- 1.0.0: Initial release with binary, multi-class, and anomaly detection
- Future versions will include improvements and new features

**Model Registry**: All trained models are registered with metadata including:
- Training timestamp
- Dataset used
- Hyperparameters
- Performance metrics
- Feature importance

## Citation

If you use Sentinel AI in your research or work, please cite:

```
Sentinel AI: An Explainable AI-Powered Security Operations Center Assistant
Version 1.0.0
https://github.com/your-org/sentinel-ai
```

## Contact and Support

**Issues**: Report issues via GitHub issue tracker  
**Questions**: Contact via project support channels  
**Documentation**: See project documentation for detailed guides

## Disclaimer

**Important**: Sentinel AI is designed as a defensive security tool to assist human analysts. It should not be used for:
- Unauthorized surveillance
- Privacy violations
- Offensive operations
- Any malicious activities

The system provides AI-assisted analysis but requires human validation for all findings. Model explanations are evidence, not proof of causation. MITRE ATT&CK mappings are heuristic approximations that must be validated by security analysts.

**Performance Metrics**: Benchmark results do not guarantee production SOC performance. Real-world performance may vary significantly based on network environment, threat landscape, and implementation details.

**Liability**: The authors and contributors are not responsible for any misuse of this system or any decisions made based on its recommendations.
