#!/usr/bin/env python
"""Script to generate synthetic data for Sentinel AI."""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.data.synthetic import generate_all_synthetic_data
from src.utils.logger import setup_logger, get_logger

logger = get_logger(__name__)


def main():
    """Main function to generate synthetic data."""
    logger.info("Starting synthetic data generation")
    
    try:
        output_dir = generate_all_synthetic_data()
        logger.info(f"Synthetic data generated successfully in {output_dir}")
        print(f"✓ Synthetic data generated in {output_dir}")
        print("  - synthetic_alerts.csv")
        print("  - synthetic_assets.csv")
        print("  - synthetic_users.csv")
        print("  - synthetic_incidents.csv")
    except Exception as e:
        logger.error(f"Failed to generate synthetic data: {e}")
        print(f"✗ Failed to generate synthetic data: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
