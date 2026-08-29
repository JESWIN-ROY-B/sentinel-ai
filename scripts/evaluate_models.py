#!/usr/bin/env python
"""Evaluation script for Sentinel AI models."""

import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.data.loader import load_data_for_training
from src.data.preprocessing import preprocess_pipeline
from src.models.predict import ModelPredictor
from src.models.evaluate import ModelEvaluator
from src.utils.logger import setup_logger, get_logger

logger = get_logger(__name__)


def main():
    """Main evaluation function."""
    parser = argparse.ArgumentParser(description='Evaluate Sentinel AI models')
    parser.add_argument('--data', type=str, help='Path to evaluation data file')
    parser.add_argument('--dataset', type=str, default='synthetic', help='Dataset name (synthetic, UNSW-NB15)')
    parser.add_argument('--model-type', type=str, default='all',
                       choices=['binary', 'multiclass', 'anomaly', 'all'],
                       help='Type of model to evaluate')
    
    args = parser.parse_args()
    
    logger.info("Starting model evaluation")
    logger.info(f"Dataset: {args.dataset}")
    logger.info(f"Model type: {args.model_type}")
    
    # Load data
    logger.info("Loading dataset...")
    features, labels, info = load_data_for_training(args.dataset, args.data)
    
    if labels is None:
        logger.error("No labels found in dataset. Cannot evaluate models.")
        return
    
    logger.info(f"Loaded {len(features)} samples")
    
    # Preprocess
    logger.info("Preprocessing data...")
    features_processed, labels_processed, preprocessor = preprocess_pipeline(
        features.join(labels.rename('label')), 'label', save_preprocessor=False
    )
    
    # Load predictor
    logger.info("Loading trained models...")
    predictor = ModelPredictor()
    predictor.load_binary_model()
    predictor.load_multiclass_model()
    predictor.load_anomaly_detector()
    
    # Initialize evaluator
    evaluator = ModelEvaluator()
    
    # Evaluate based on request
    if args.model_type in ['binary', 'all']:
        if predictor.binary_model is not None:
            logger.info("Evaluating binary classifier...")
            try:
                predictions, probabilities = predictor.predict_binary(features_processed)
                metrics = evaluator.evaluate_binary(labels_processed, predictions, probabilities)
                evaluator.save_metrics(metrics)
                
                report = evaluator.generate_evaluation_report(metrics)
                logger.info(f"\nBinary Model Evaluation Report:\n{report}")
            except Exception as e:
                logger.error(f"Failed to evaluate binary model: {e}")
        else:
            logger.warning("Binary model not loaded")
    
    if args.model_type in ['multiclass', 'all']:
        if predictor.multiclass_model is not None:
            logger.info("Evaluating multi-class classifier...")
            try:
                predictions, probabilities = predictor.predict_multiclass(features_processed)
                class_names = [str(i) for i in range(len(probabilities[0]))]
                metrics = evaluator.evaluate_multiclass(labels_processed, predictions, None, class_names)
                evaluator.save_metrics(metrics)
                
                report = evaluator.generate_evaluation_report(metrics)
                logger.info(f"\nMulticlass Model Evaluation Report:\n{report}")
            except Exception as e:
                logger.error(f"Failed to evaluate multiclass model: {e}")
        else:
            logger.warning("Multiclass model not loaded")
    
    if args.model_type in ['anomaly', 'all']:
        if predictor.anomaly_detector is not None:
            logger.info("Evaluating anomaly detector...")
            try:
                predictions, scores = predictor.predict_anomaly(features_processed)
                metrics = evaluator.evaluate_anomaly(labels_processed, predictions, scores)
                evaluator.save_metrics(metrics)
                
                report = evaluator.generate_evaluation_report(metrics)
                logger.info(f"\nAnomaly Detector Evaluation Report:\n{report}")
            except Exception as e:
                logger.error(f"Failed to evaluate anomaly detector: {e}")
        else:
            logger.warning("Anomaly detector not loaded")
    
    logger.info("Evaluation complete")


if __name__ == "__main__":
    main()
