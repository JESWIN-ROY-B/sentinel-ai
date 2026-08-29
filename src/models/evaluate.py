"""Model evaluation and metrics generation."""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
import logging
from pathlib import Path
from datetime import datetime
import json
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, precision_recall_curve, auc,
    confusion_matrix, classification_report
)

from ..utils.logger import get_logger
from ..utils.paths import get_metrics_dir, get_figures_dir
from ..utils.helpers import safe_float

logger = get_logger(__name__)


class ModelEvaluator:
    """Evaluate machine learning models for intrusion detection."""
    
    def __init__(self):
        """Initialize the model evaluator."""
        self.metrics = {}
        self.figures = {}
        
        # Set plotting style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (10, 6)
    
    def evaluate_binary(self, 
                      y_true: np.ndarray, 
                      y_pred: np.ndarray,
                      y_prob: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """Evaluate binary classification model."""
        logger.info("Evaluating binary classification model")
        
        metrics = {
            'model_type': 'binary',
            'evaluation_timestamp': datetime.now().isoformat(),
            'sample_count': len(y_true)
        }
        
        # Basic metrics
        metrics['accuracy'] = float(accuracy_score(y_true, y_pred))
        metrics['precision'] = float(precision_score(y_true, y_pred, average='binary', zero_division=0))
        metrics['recall'] = float(recall_score(y_true, y_pred, average='binary', zero_division=0))
        metrics['f1_score'] = float(f1_score(y_true, y_pred, average='binary', zero_division=0))
        
        # ROC-AUC if probabilities available
        if y_prob is not None:
            try:
                metrics['roc_auc'] = float(roc_auc_score(y_true, y_prob))
                
                # PR-AUC
                precision, recall, _ = precision_recall_curve(y_true, y_prob)
                metrics['pr_auc'] = float(auc(recall, precision))
            except Exception as e:
                logger.warning(f"Could not calculate ROC-AUC: {e}")
                metrics['roc_auc'] = None
                metrics['pr_auc'] = None
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        metrics['true_positives'] = int(cm[1, 1])
        metrics['true_negatives'] = int(cm[0, 0])
        metrics['false_positives'] = int(cm[0, 1])
        metrics['false_negatives'] = int(cm[1, 0])
        
        # Class distribution
        metrics['class_distribution'] = {
            'normal': int(np.sum(y_true == 0)),
            'attack': int(np.sum(y_true == 1))
        }
        
        logger.info(f"Binary evaluation complete: Accuracy={metrics['accuracy']:.3f}, F1={metrics['f1_score']:.3f}")
        
        return metrics
    
    def evaluate_multiclass(self,
                          y_true: np.ndarray,
                          y_pred: np.ndarray,
                          y_prob: Optional[np.ndarray] = None,
                          class_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Evaluate multi-class classification model."""
        logger.info("Evaluating multi-class classification model")
        
        metrics = {
            'model_type': 'multiclass',
            'evaluation_timestamp': datetime.now().isoformat(),
            'sample_count': len(y_true)
        }
        
        # Basic metrics
        metrics['accuracy'] = float(accuracy_score(y_true, y_pred))
        metrics['precision_macro'] = float(precision_score(y_true, y_pred, average='macro', zero_division=0))
        metrics['recall_macro'] = float(recall_score(y_true, y_pred, average='macro', zero_division=0))
        metrics['f1_macro'] = float(f1_score(y_true, y_pred, average='macro', zero_division=0))
        metrics['precision_weighted'] = float(precision_score(y_true, y_pred, average='weighted', zero_division=0))
        metrics['recall_weighted'] = float(recall_score(y_true, y_pred, average='weighted', zero_division=0))
        metrics['f1_weighted'] = float(f1_score(y_true, y_pred, average='weighted', zero_division=0))
        
        # Per-class metrics
        if class_names is None:
            class_names = [f"Class_{i}" for i in np.unique(y_true)]
        
        report = classification_report(y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0)
        metrics['per_class_metrics'] = report
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        
        # Class distribution
        unique, counts = np.unique(y_true, return_counts=True)
        metrics['class_distribution'] = {
            str(class_names[i] if i < len(class_names) else f"Class_{i}"): int(count) 
            for i, count in zip(unique, counts)
        }
        
        logger.info(f"Multiclass evaluation complete: Accuracy={metrics['accuracy']:.3f}, F1-macro={metrics['f1_macro']:.3f}")
        
        return metrics
    
    def evaluate_anomaly(self,
                       y_true: np.ndarray,
                       y_pred: np.ndarray,
                       anomaly_scores: np.ndarray) -> Dict[str, Any]:
        """Evaluate anomaly detection model."""
        logger.info("Evaluating anomaly detection model")
        
        metrics = {
            'model_type': 'anomaly',
            'evaluation_timestamp': datetime.now().isoformat(),
            'sample_count': len(y_true)
        }
        
        # Basic metrics (treating anomaly detection as binary classification)
        metrics['accuracy'] = float(accuracy_score(y_true, y_pred))
        metrics['precision'] = float(precision_score(y_true, y_pred, average='binary', zero_division=0))
        metrics['recall'] = float(recall_score(y_true, y_pred, average='binary', zero_division=0))
        metrics['f1_score'] = float(f1_score(y_true, y_pred, average='binary', zero_division=0))
        
        # Anomaly score statistics
        metrics['anomaly_score_stats'] = {
            'mean': float(np.mean(anomaly_scores)),
            'std': float(np.std(anomaly_scores)),
            'min': float(np.min(anomaly_scores)),
            'max': float(np.max(anomaly_scores)),
            'median': float(np.median(anomaly_scores))
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        metrics['true_positives'] = int(cm[1, 1])
        metrics['true_negatives'] = int(cm[0, 0])
        metrics['false_positives'] = int(cm[0, 1])
        metrics['false_negatives'] = int(cm[1, 0])
        
        logger.info(f"Anomaly evaluation complete: Accuracy={metrics['accuracy']:.3f}, F1={metrics['f1_score']:.3f}")
        
        return metrics
    
    def plot_confusion_matrix(self, 
                             cm: np.ndarray,
                             class_names: List[str],
                             title: str = "Confusion Matrix",
                             save_path: Optional[Path] = None) -> Path:
        """Plot confusion matrix."""
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=class_names, yticklabels=class_names)
        plt.title(title)
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        
        if save_path is None:
            figures_dir = get_figures_dir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = figures_dir / f"confusion_matrix_{timestamp}.png"
        
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Confusion matrix saved to {save_path}")
        return save_path
    
    def plot_roc_curve(self,
                      y_true: np.ndarray,
                      y_prob: np.ndarray,
                      title: str = "ROC Curve",
                      save_path: Optional[Path] = None) -> Path:
        """Plot ROC curve."""
        from sklearn.metrics import roc_curve
        
        fpr, tpr, thresholds = roc_curve(y_true, y_prob)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(title)
        plt.legend(loc="lower right")
        plt.tight_layout()
        
        if save_path is None:
            figures_dir = get_figures_dir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = figures_dir / f"roc_curve_{timestamp}.png"
        
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"ROC curve saved to {save_path}")
        return save_path
    
    def plot_precision_recall_curve(self,
                                   y_true: np.ndarray,
                                   y_prob: np.ndarray,
                                   title: str = "Precision-Recall Curve",
                                   save_path: Optional[Path] = None) -> Path:
        """Plot precision-recall curve."""
        precision, recall, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = auc(recall, precision)
        
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, color='blue', lw=2, label=f'PR curve (AUC = {pr_auc:.2f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title(title)
        plt.legend(loc="lower left")
        plt.tight_layout()
        
        if save_path is None:
            figures_dir = get_figures_dir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = figures_dir / f"pr_curve_{timestamp}.png"
        
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Precision-recall curve saved to {save_path}")
        return save_path
    
    def save_metrics(self, metrics: Dict[str, Any], save_path: Optional[Path] = None) -> Path:
        """Save metrics to JSON file."""
        if save_path is None:
            metrics_dir = get_metrics_dir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_type = metrics.get('model_type', 'unknown')
            save_path = metrics_dir / f"{model_type}_metrics_{timestamp}.json"
        
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(save_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        logger.info(f"Metrics saved to {save_path}")
        return save_path
    
    def generate_evaluation_report(self, metrics: Dict[str, Any]) -> str:
        """Generate a human-readable evaluation report."""
        report = []
        report.append("=" * 50)
        report.append("MODEL EVALUATION REPORT")
        report.append("=" * 50)
        
        model_type = metrics.get('model_type', 'unknown')
        report.append(f"Model Type: {model_type.upper()}")
        report.append(f"Evaluation Timestamp: {metrics.get('evaluation_timestamp', 'N/A')}")
        report.append(f"Sample Count: {metrics.get('sample_count', 0)}")
        report.append("")
        
        if model_type == 'binary':
            report.append("BINARY CLASSIFICATION METRICS:")
            report.append(f"  Accuracy: {metrics.get('accuracy', 0):.4f}")
            report.append(f"  Precision: {metrics.get('precision', 0):.4f}")
            report.append(f"  Recall: {metrics.get('recall', 0):.4f}")
            report.append(f"  F1-Score: {metrics.get('f1_score', 0):.4f}")
            
            if metrics.get('roc_auc') is not None:
                report.append(f"  ROC-AUC: {metrics.get('roc_auc', 0):.4f}")
            if metrics.get('pr_auc') is not None:
                report.append(f"  PR-AUC: {metrics.get('pr_auc', 0):.4f}")
            
            report.append("")
            report.append("CONFUSION MATRIX:")
            report.append(f"  True Positives: {metrics.get('true_positives', 0)}")
            report.append(f"  True Negatives: {metrics.get('true_negatives', 0)}")
            report.append(f"  False Positives: {metrics.get('false_positives', 0)}")
            report.append(f"  False Negatives: {metrics.get('false_negatives', 0)}")
        
        elif model_type == 'multiclass':
            report.append("MULTI-CLASS CLASSIFICATION METRICS:")
            report.append(f"  Accuracy: {metrics.get('accuracy', 0):.4f}")
            report.append(f"  Precision (Macro): {metrics.get('precision_macro', 0):.4f}")
            report.append(f"  Recall (Macro): {metrics.get('recall_macro', 0):.4f}")
            report.append(f"  F1-Score (Macro): {metrics.get('f1_macro', 0):.4f}")
            report.append(f"  Precision (Weighted): {metrics.get('precision_weighted', 0):.4f}")
            report.append(f"  Recall (Weighted): {metrics.get('recall_weighted', 0):.4f}")
            report.append(f"  F1-Score (Weighted): {metrics.get('f1_weighted', 0):.4f}")
            
            if 'per_class_metrics' in metrics:
                report.append("")
                report.append("PER-CLASS METRICS:")
                for class_name, class_metrics in metrics['per_class_metrics'].items():
                    if isinstance(class_metrics, dict) and 'f1-score' in class_metrics:
                        report.append(f"  {class_name}:")
                        report.append(f"    Precision: {class_metrics.get('precision', 0):.4f}")
                        report.append(f"    Recall: {class_metrics.get('recall', 0):.4f}")
                        report.append(f"    F1-Score: {class_metrics.get('f1-score', 0):.4f}")
        
        elif model_type == 'anomaly':
            report.append("ANOMALY DETECTION METRICS:")
            report.append(f"  Accuracy: {metrics.get('accuracy', 0):.4f}")
            report.append(f"  Precision: {metrics.get('precision', 0):.4f}")
            report.append(f"  Recall: {metrics.get('recall', 0):.4f}")
            report.append(f"  F1-Score: {metrics.get('f1_score', 0):.4f}")
            
            if 'anomaly_score_stats' in metrics:
                stats = metrics['anomaly_score_stats']
                report.append("")
                report.append("ANOMALY SCORE STATISTICS:")
                report.append(f"  Mean: {stats.get('mean', 0):.4f}")
                report.append(f"  Std: {stats.get('std', 0):.4f}")
                report.append(f"  Min: {stats.get('min', 0):.4f}")
                report.append(f"  Max: {stats.get('max', 0):.4f}")
                report.append(f"  Median: {stats.get('median', 0):.4f}")
        
        # Class distribution
        if 'class_distribution' in metrics:
            report.append("")
            report.append("CLASS DISTRIBUTION:")
            for class_name, count in metrics['class_distribution'].items():
                report.append(f"  {class_name}: {count}")
        
        report.append("")
        report.append("=" * 50)
        
        return "\n".join(report)


def evaluate_model(model_type: str,
                  y_true: np.ndarray,
                  y_pred: np.ndarray,
                  y_prob: Optional[np.ndarray] = None,
                  class_names: Optional[List[str]] = None,
                  save_results: bool = True) -> Dict[str, Any]:
    """Evaluate a model and save results."""
    evaluator = ModelEvaluator()
    
    if model_type == 'binary':
        metrics = evaluator.evaluate_binary(y_true, y_pred, y_prob)
    elif model_type == 'multiclass':
        metrics = evaluator.evaluate_multiclass(y_true, y_pred, y_prob, class_names)
    elif model_type == 'anomaly':
        if y_prob is None:
            raise ValueError("Anomaly scores required for anomaly evaluation")
        metrics = evaluator.evaluate_anomaly(y_true, y_pred, y_prob)
    else:
        raise ValueError(f"Unknown model type: {model_type}")
    
    if save_results:
        evaluator.save_metrics(metrics)
        
        # Generate plots for binary classification
        if model_type == 'binary' and y_prob is not None:
            evaluator.plot_roc_curve(y_true, y_prob)
            evaluator.plot_precision_recall_curve(y_true, y_prob)
        
        # Plot confusion matrix
        if class_names:
            cm = np.array(metrics['confusion_matrix'])
            evaluator.plot_confusion_matrix(cm, class_names)
    
    # Generate report
    report = evaluator.generate_evaluation_report(metrics)
    logger.info(f"Evaluation report:\n{report}")
    
    return metrics


if __name__ == "__main__":
    # Test evaluation
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier
    
    # Generate synthetic data
    X = np.random.randn(1000, 10)
    y = np.random.randint(0, 2, 1000)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    model = RandomForestClassifier(random_state=42)
    model.fit(X_train, y_train)
    
    # Make predictions
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    
    # Evaluate
    metrics = evaluate_model('binary', y_test, y_pred, y_prob, save_results=False)
    print(f"Evaluation metrics: {metrics}")
