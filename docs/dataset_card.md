# Dataset Card: UNSW-NB15

## Dataset Overview

**Dataset Name**: UNSW-NB15  
**Version**: 2015  
**Creators**: Australian Centre for Cyber Security (ACCS)  
**Release Date**: 2015  
**License**: Research/Educational use  
**Dataset Size**: ~2.5 million records (combined training and testing)  
**Primary Use**: Network intrusion detection research  

## Dataset Description

The UNSW-NB15 dataset was created by the Cyber Range Lab of the Australian Centre for Cyber Security (ACCS) in 2015. It provides a comprehensive set of network traffic data for intrusion detection research, containing both normal and malicious traffic patterns.

### Dataset Characteristics

- **Total Records**: ~2.5 million network flow records
- **Training Set**: ~175,000 records (cleaned and labeled)
- **Testing Set**: ~83,000 records (cleaned and labeled)
- **Features**: 49 network flow features
- **Attack Categories**: 10 classes (including Normal)
- **Capture Method**: IXIA PerfectStorm tool
- **Network Environment**: Simulated cyber range

## Dataset Composition

### Attack Categories

The dataset includes the following attack categories:

1. **Normal**: Legitimate network traffic
2. **Fuzzers**: Vulnerability probing and fuzzing attacks
3. **Analysis**: Network analysis and probing
4. **Backdoors**: Backdoor attacks and remote access
5. **DoS**: Denial of Service attacks
6. **Exploits**: Exploitation of known vulnerabilities
7. **Generic**: Generic attack patterns
8. **Reconnaissance**: Network reconnaissance and scanning
9. **Shellcode**: Shellcode execution attacks
10. **Worms**: Worm propagation and lateral movement

### Feature Set

The dataset includes 49 features categorized as follows:

**Flow Features**:
- Source/Destination IP addresses
- Source/Destination ports
- Protocol (TCP, UDP, ICMP, ARP)
- Service (HTTP, FTP, SMTP, DNS, etc.)
- Connection state

**Traffic Features**:
- Duration (flow duration)
- Source/Destination bytes
- Source/Destination packets
- Source/Destination TTL
- Source/Destination load
- Source/Destination loss
- Source/Destination inter-packet time
- Source/Destination jitter

**Statistical Features**:
- TCP window sizes
- TCP round-trip time
- SYN/ACK times
- Mean packet sizes
- Transaction depth
- Response body length

**Count-based Features**:
- Count of connections to same service
- Count of connections with same state
- Count of connections to same destination
- Count of connections from same source
- Various time-based counts

**Additional Features**:
- FTP login indicator
- FTP command count
- Additional flow statistics

## Data Preprocessing

### Recommended Preprocessing Steps

1. **Data Cleaning**:
   - Handle missing values (mean/median imputation)
   - Replace infinite values
   - Remove duplicate records
   - Standardize column names

2. **Feature Engineering**:
   - Remove leakage columns (IP addresses, ports)
   - Encode categorical variables (label/one-hot encoding)
   - Scale numerical features (standard/minmax scaling)
   - Create derived features if needed

3. **Label Processing**:
   - Binary label: 0 = Normal, 1 = Attack
   - Multi-class label: Attack category names
   - Handle class imbalance (class weighting)

### Data Splitting

**Official Split**: The dataset provides official training and testing sets

**Alternative Split** (if official split not used):
- Training: 70%
- Validation: 10%
- Testing: 20%

**Stratification**: Use stratified sampling to maintain class distribution

## Dataset Statistics

### Class Distribution

**Training Set** (approximate):
- Normal: ~45%
- Exploits: ~15%
- DoS: ~12%
- Reconnaissance: ~10%
- Analysis: ~8%
- Backdoors: ~7%
- Fuzzers: ~5%
- Shellcode: ~4%
- Worms: ~3%
- Generic: ~1%

**Testing Set**: Similar distribution to training set

### Feature Statistics

**Numerical Features**:
- Range: Varies significantly by feature
- Scale: Some features have very large ranges
- Distribution: Many features are heavily skewed
- Missing values: Minimal in cleaned dataset

**Categorical Features**:
- Protocol: 4 main types (TCP, UDP, ICMP, ARP)
- Service: ~13 main services
- State: ~11 connection states

## Dataset Limitations

### Temporal Bias

1. **Outdated Patterns**: Dataset from 2015 may not reflect current threats
2. **Protocol Evolution**: New protocols not represented
3. **Attack Evolution**: Modern attack techniques may be missing

### Geographic Bias

1. **Regional Patterns**: Australian cyber range may not represent global patterns
2. **Cultural Factors**: Usage patterns may vary by region
3. **Infrastructure**: Network infrastructure may differ

### Environmental Bias

1. **Simulated Environment**: Cyber range may not reflect real networks
2. **Limited Diversity**: Limited set of applications and services
3. **Synthetic Attacks**: Some attacks may be artificially generated

### Quality Issues

1. **Label Noise**: Some labels may be incorrect
2. **Feature Quality**: Some features may have measurement errors
3. **Completeness**: Not all real-world scenarios are represented

## Ethical Considerations

### Privacy

1. **IP Addresses**: Dataset contains IP addresses (should be handled carefully)
2. **Network Patterns**: May reveal organizational network structures
3. **Traffic Content**: May contain sensitive information

### Usage Guidelines

1. **Research Only**: Intended for research and educational purposes
2. **No Surveillance**: Should not be used for unauthorized surveillance
3. **Attribution**: Proper attribution to ACCS required
4. **Compliance**: Must comply with applicable laws and regulations

### Data Protection

1. **No PII**: Dataset should not contain personally identifiable information
2. **Secure Storage**: Store dataset securely
3. **Access Control**: Limit access to authorized personnel
4. **Deletion**: Delete dataset when no longer needed

## Dataset Access

### Official Sources

1. **ACCS Website**: Australian Centre for Cyber Security
2. **Research Repositories**: Various academic repositories
3. **Kaggle**: Available on Kaggle dataset platform
4. **UNSW Repository**: University of New South Wales repositories

### File Format

**Primary Format**: CSV files

**File Names**:
- UNSW_NB15_training-set.csv
- UNSW_NB15_testing-set.csv
- UNSW_NB15_features.csv (feature descriptions)

### File Size

- Training set: ~200 MB (compressed)
- Testing set: ~100 MB (compressed)
- Features file: ~1 MB

## Usage in Sentinel AI

### Integration

Sentinel AI uses the UNSW-NB15 dataset as the primary training data source:

1. **Data Loading**: Custom loader for UNSW-NB15 format
2. **Preprocessing**: Automatic preprocessing pipeline
3. **Model Training**: Trains all three model types
4. **Evaluation**: Comprehensive performance evaluation
5. **Benchmarking**: Establishes performance baselines

### Model Performance

**Expected Performance** (on UNSW-NB15):
- Binary classifier: 85-90% accuracy
- Multi-class classifier: 75-80% accuracy
- Anomaly detector: 70-80% accuracy

**Note**: Performance varies by attack category and configuration

### Fallback to Synthetic Data

If UNSW-NB15 is not available, Sentinel AI can use synthetic data:
- Fully functional demo mode
- Synthetic patterns based on real attack characteristics
- Clearly labeled as demo-only
- Not representative of real-world performance

## Comparison with Other Datasets

### Similar Datasets

1. **KDD Cup 99**: Older dataset, similar purpose
2. **NSL-KDD**: Improved version of KDD Cup 99
3. **CIC-IDS2017**: More recent, includes newer attacks
4. **CTU-13**: Botnet traffic dataset

### Advantages of UNSW-NB15

1. **Modern**: More recent than KDD Cup 99
2. **Comprehensive**: Wide range of attack types
3. **Realistic**: Generated in realistic cyber range
4. **Labeled**: Good quality labels
5. **Size**: Large enough for training complex models

### Disadvantages

1. **Age**: Still somewhat outdated (2015)
2. **Synthetic**: Some artificially generated traffic
3. **Limited**: Limited to network flow features
4. **Bias**: Regional and environmental biases

## Best Practices

### Data Handling

1. **Validation**: Always validate data before training
2. **Preprocessing**: Follow recommended preprocessing steps
3. **Splitting**: Use official splits when available
4. **Documentation**: Document all preprocessing steps

### Model Training

1. **Cross-validation**: Use cross-validation for robust evaluation
2. **Class Imbalance**: Handle class imbalance appropriately
3. **Feature Selection**: Remove leakage and irrelevant features
4. **Hyperparameter Tuning**: Tune hyperparameters for optimal performance

### Evaluation

1. **Multiple Metrics**: Use multiple evaluation metrics
2. **Per-class Analysis**: Analyze performance by attack category
3. **Error Analysis**: Analyze false positives and false negatives
4. **Validation**: Validate on held-out test set

## Future Datasets

### Planned Support

Sentinel AI architecture supports future addition of:

1. **CIC-IDS2017**: More recent IDS dataset
2. **CSE-CIC-IDS2018**: Extended CIC dataset
3. **TON_IoT**: IoT security dataset
4. **Bot-IoT**: Botnet IoT traffic
5. **CTU-13**: Botnet traffic dataset

### Adapter Pattern

The system uses an adapter pattern for easy dataset integration:

```python
class NewDatasetAdapter(DatasetAdapter):
    def load(self, file_path: str) -> pd.DataFrame:
        # Custom loading logic
        pass
    
    def standardize(self, df: pd.DataFrame) -> pd.DataFrame:
        # Custom standardization logic
        pass
```

## Citation

If you use the UNSW-NB15 dataset, please cite:

```
Moustafa, Nour, and Slay, Jill. "UNSW-NB15: a comprehensive data set for network intrusion detection systems." 
2015 International Conference on Multimedia Big Data. IEEE, 2015.
```

## Contact and Support

**Dataset Issues**: Contact ACCS for dataset-specific issues  
**Integration Issues**: Contact Sentinel AI project maintainers  
**Documentation**: See project documentation for integration details

## Disclaimer

**Important**: The UNSW-NB15 dataset is provided for research and educational purposes only. It should not be used for:
- Unauthorized surveillance
- Privacy violations
- Offensive operations
- Any malicious activities

The dataset contains network traffic data that may include IP addresses and other network identifiers. Handle this data in accordance with privacy regulations and organizational policies.

**Performance**: Model performance on UNSW-NB15 does not guarantee performance on real-world data. Results may vary significantly based on network environment, threat landscape, and implementation details.

**Liability**: The dataset creators and Sentinel AI project are not responsible for any misuse of this dataset or any decisions made based on models trained on it.
