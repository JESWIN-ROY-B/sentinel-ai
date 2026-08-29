# Data Directory

This directory contains all data files for Sentinel AI.

## Directory Structure

- `raw/` - Raw dataset files (UNSW-NB15 and other datasets)
- `processed/` - Processed and preprocessed data files
- `sample/` - Synthetic sample data for demonstration

## Dataset Placement

### UNSW-NB15 Dataset

Place your UNSW-NB15 CSV files in the `data/raw/` directory:

```
data/raw/
├── UNSW_NB15_training-set.csv
├── UNSW_NB15_testing-set.csv
└── UNSW_NB15_features.csv
```

### Other Datasets

Additional datasets can be placed in the `data/raw/` directory. The system will attempt to detect and process them based on file naming conventions.

## Schema Information

### UNSW-NB15 Schema

The UNSW-NB15 dataset contains the following main features:

- `srcip` - Source IP address
- `sport` - Source port
- `dstip` - Destination IP address
- `dsport` - Destination port
- `proto` - Protocol (tcp, udp, icmp, etc.)
- `service` - Service (http, ftp, smtp, etc.)
- `state` - Connection state
- `dur` - Flow duration
- `sbytes` - Source to destination bytes
- `dbytes` - Destination to source bytes
- And many more network flow features...

### Label Columns

The system supports multiple label column variants:
- `label` - Binary label (0=Normal, 1=Attack)
- `attack_cat` - Attack category (Normal, Fuzzers, Analysis, etc.)

## Preprocessing

The preprocessing pipeline includes:

1. **Schema Validation** - Ensures expected columns are present
2. **Missing Value Handling** - Configurable strategies (mean, median, drop)
3. **Infinite Value Replacement** - Replaces +/- infinity with appropriate values
4. **Duplicate Removal** - Removes duplicate rows
5. **Categorical Encoding** - Label or one-hot encoding
6. **Numerical Scaling** - Standard, minmax, robust scaling, or none
7. **Feature Selection** - Removes leakage columns and identifiers

## Data Privacy

**Important Security Guidelines:**

- Do not commit real organizational data to this repository
- Do not include credentials, API keys, or secrets
- Mask sensitive information in demo/screenshot modes
- Follow organizational data governance policies
- Comply with applicable privacy laws and regulations

## Synthetic Data

The `data/sample/` directory contains synthetic data for demonstration:

- `synthetic_alerts.csv` - Sample network alerts
- `synthetic_assets.csv` - Sample asset inventory
- `synthetic_users.csv` - Sample user accounts
- `synthetic_incidents.csv` - Sample incidents

**Note:** This data is clearly labeled as demo-only and is not representative of real-world performance or patterns.

## Data Licensing

When using real datasets:

- Review and comply with dataset licensing terms
- Cite the dataset appropriately in your work
- Follow ethical use guidelines
- Respect data privacy requirements

## File Formats

Supported formats:
- CSV (primary)
- Parquet (optional, future support)

## .gitignore

The `.gitignore` file is configured to:
- Exclude raw datasets from version control
- Exclude processed data files
- Include only sample synthetic data
- Protect sensitive information

## Data Validation

The system includes comprehensive validation:

- Schema validation before processing
- Data type checking
- Range validation for numerical features
- Categorical value validation
- Label distribution analysis

## Backups

Consider implementing a backup strategy for:
- Raw dataset files
- Processed data
- Model artifacts
- Configuration files

## Data Quality

Monitor data quality metrics:
- Missing value percentages
- Duplicate rates
- Label distribution balance
- Feature distribution statistics
- Outlier detection results

## Troubleshooting

### Common Issues

1. **Schema Mismatch**: Ensure column names match expected format
2. **Missing Labels**: Verify label column is present and correctly named
3. **Encoding Issues**: Check file encoding (UTF-8 recommended)
4. **Memory Issues**: Consider sampling for large datasets

### Support

For data-related issues, consult the documentation or open an issue in the repository.
