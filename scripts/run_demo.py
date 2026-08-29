#!/usr/bin/env python
"""Demo script for Sentinel AI - Quick start for hackathon demonstrations."""

import sys
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.utils.logger import setup_logger, get_logger

logger = get_logger(__name__)


def check_dependencies():
    """Check if required dependencies are installed."""
    logger.info("Checking dependencies...")
    
    required_packages = [
        'streamlit', 'pandas', 'numpy', 'scikit-learn', 
        'plotly', 'pyyaml', 'python-dotenv'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.error(f"Missing packages: {missing_packages}")
        logger.error("Please run: pip install -r requirements.txt")
        return False
    
    logger.info("All dependencies installed")
    return True


def generate_synthetic_data():
    """Generate synthetic data for demo."""
    logger.info("Generating synthetic data...")
    
    try:
        from src.data.synthetic import generate_all_synthetic_data
        output_dir = generate_all_synthetic_data()
        logger.info(f"Synthetic data generated in {output_dir}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate synthetic data: {e}")
        return False


def run_streamlit():
    """Run the Streamlit dashboard."""
    logger.info("Starting Streamlit dashboard...")
    
    try:
        app_path = project_root / "app.py"
        subprocess.run(["streamlit", "run", str(app_path)], check=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to run Streamlit: {e}")
        return False
    except KeyboardInterrupt:
        logger.info("Dashboard stopped by user")
        return True


def main():
    """Main demo function."""
    print("=" * 60)
    print("SENTINEL AI - DEMO MODE")
    print("=" * 60)
    print()
    print("Starting Sentinel AI in demo mode...")
    print()
    
    # Check dependencies
    if not check_dependencies():
        print("❌ Dependency check failed")
        return 1
    
    # Generate synthetic data
    print("📊 Generating synthetic data...")
    if not generate_synthetic_data():
        print("❌ Synthetic data generation failed")
        return 1
    
    print("✅ Synthetic data ready")
    print()
    
    # Run Streamlit
    print("🚀 Starting Streamlit dashboard...")
    print("📱 Dashboard will open in your browser")
    print("🔒 This is DEMO MODE using synthetic data")
    print()
    print("Press Ctrl+C to stop the dashboard")
    print("-" * 60)
    print()
    
    try:
        if not run_streamlit():
            print("❌ Dashboard failed to start")
            return 1
    except KeyboardInterrupt:
        print()
        print("👋 Demo stopped by user")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
