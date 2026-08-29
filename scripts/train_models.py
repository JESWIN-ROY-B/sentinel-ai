#!/usr/bin/env python
"""Training script for Sentinel AI models."""

import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.data.loader import load_data_for_training
from src.data.preprocessing import preprocess_pipeline, split_data
from src.models.train import train_binary_classifier, train_multiclass_classifier
from src.models.anomaly import train_anomaly_detector
from src.models.evaluate import ModelEvaluator
from src.models.registry import auto_register_model
from src.utils.logger import setup_logger, get_logger

logger = get_logger(__name__)


def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description='Train Sentinel AI models')
    parser.add_argument('--data', type=str, help='Path to training data file')
    parser.add_argument('--dataset', type=str, default='synthetic', help='Dataset name (synthetic, UNSW-NB15)')
    parser.add_argument('--model-type', type=str, default='all', 
                       choices=['binary', 'multiclass', 'anomaly', 'all'],
                       help='Type of model to train')
    parser.add_argument('--test-size', type=float, default=0.2, help='Test set size')
    parser.add_argument('--validation-size', type=float, default=0.1, help='Validation set size')
    parser.add_argument('--no-save', action='store_true', help='Do not save trained models')
    
    args = parser.parse_args()
    
    logger.info("Starting model training pipeline")
    logger.info(f"Dataset: {args.dataset}")
    logger.info(f"Model type: {args.model_type}")
    
    # Load data
    logger.info("Loading dataset...")
    features, labels, info = load_data_for_training(args.dataset, args.data)
    
    if labels is None:
        logger.error("No labels found in dataset. Cannot train supervised models.")
        return
    
    logger.info(f"Loaded {len(features)} samples with {len(features.columns)} features")
    
    # Split data
    logger.info("Splitting data...")
    train_df, val_df, test_df = split_data(
        features.join(labels.rename('label')),
        label_column='label',
        test_size=args.test_size,
        validation_size=args.validation_size
    )
    
    logger.info(f"Train: {len(train_df)}, Val: {len(val_df) if val_df is not None else 0}, Test: {len(test_df)}")
    
    # Preprocess
    logger.info("Preprocessing data...")
    train_features, train_labels, preprocessor = preprocess_pipeline(
        train_df, 'label', save_preprocessor=not args.no_save
    )
    
    if val_df is not None:
        val_features, val_labels = preprocessor.transform(val_df, 'label')
    else:
        val_features, val_labels = None, None
    
    test_features, test_labels = preprocessor.transform(test_df, 'label')
    
    # Train models based on request
    models_trained = []
    
    if args.model_type in ['binary', 'all']:
        logger.info("Training binary classifier...")
        try:
            binary_model, binary_metadata = train_binary_classifier(
                train_features, train_labels, val_features, val_labels,
                save_model=not args.no_save
            )
            models_trained.append(('binary', binary_metadata))
            logger.info(f"Binary classifier trained: {binary_metadata['model_name']}")
        except Exception as e:
            logger.error(f"Failed to train binary classifier: {e}")
    
    if args.model_type in ['multiclass', 'all']:
        logger.info("Training multi-class classifier...")
        try:
            multiclass_model, multiclass_metadata = train_multiclass_classifier(
                train_features, train_labels, val_features, val_labels,
                save_model=not args.no_save
            )
            models_trained.append(('multiclass', multiclass_metadata))
            logger.info(f"Multi-class classifier trained: {multiclass_metadata['model_name']}")
        except Exception as e:
            logger.error(f"Failed to train multi-class classifier: {e}")
    
    if args.model_type in ['anomaly', 'all']:
        logger.info("Training anomaly detector...")
        try:
            anomaly_model, anomaly_metadata = train_anomaly_detector(
                train_features, train_labels,
                save_model=not args.no_save
            )
            models_trained.append(('anomaly', anomaly_metadata))
            logger.info(f"Anomaly detector trained: {anomaly_metadata['model_name']}")
        except Exception as e:
            logger.error(f"Failed to train anomaly detector: {e}")
    
    # Evaluate models
    if not args.no_save:
        logger.info("Evaluating models...")
        evaluator = ModelEvaluator()
        
        for model_type, metadata in models_trained:
            try:
                if model_type == 'binary':
                    from src.models.predict import ModelPredictor
                    predictor = ModelPredictor()
                    if predictor.load_binary_model():
                        predictions, probabilities = predictor.predict_binary(test_features)
                        metrics = evaluator.evaluate_binary(test_labels, predictions, probabilities)
                        evaluator.save_metrics(metrics)
                        logger.info(f"Binary model evaluation: Accuracy={metrics['accuracy']:.4f}")
                
                elif model_type == 'multiclass':
                    from src.models.predict import ModelPredictor
                    predictor = ModelPredictor()
                    if predictor.load_multiclass_model():
                        predictions, probabilities = predictor.predict_multiclass(test_features)
                        class_names = [str(i) for i in range(len(probabilities[0]))]
                        metrics = evaluator.evaluate_multiclass(test_labels, predictions, None, class_names)
                        evaluator.save_metrics(metrics)
                        logger.info(f"Multiclass model evaluation: Accuracy={metrics['accuracy']:.4f}")
                
                elif model_type == 'anomaly':
                    from src.models.predict import ModelPredictor
                    predictor = ModelPredictor()
                    if predictor.load_anomaly_detector():
                        predictions, scores = predictor.predict_anomaly(test_features)
                        metrics = evaluator.evaluate_anomaly(test_labels, predictions, scores)
                        evaluator.save_metrics(metrics)
                        logger.info(f"Anomaly detector evaluation: Accuracy={metrics['accuracy']:.4f}")
            
            except Exception as e:
                logger.error(f"Failed to evaluate {model_type} model: {e}")
    
    logger.info("Training pipeline complete")
    logger.info(f"Models trained: {len(models_trained)}")


if __name__ == "__main__":
    main()
