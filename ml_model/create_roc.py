#!/usr/bin/env python3
"""
ROC Curve Generator for DDoS Detection Model

Loads the trained Random Forest model and scaler, recreates the test set
using the same 75/25 stratified split (random_state=42), generates
probability predictions, and plots the ROC curve with AUC score.

Prerequisites:
    - flow_model.pkl and scaler.pkl must exist (run train_model.py first)
    - ../datasets/flow_dataset.csv must exist

Output:
    - roc_curve.png: ROC curve visualization saved in this directory

Usage:
    cd ml_model
    python3 create_roc.py

    With custom dataset:
    python3 create_roc.py --dataset /path/to/dataset.csv

"""

from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import train_test_split
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for saving without display
import matplotlib.pyplot as plt
import joblib
import pandas as pd
import numpy as np
import argparse
import os
import sys

# Import feature definitions from the single source of truth
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from utilities.feature_extractor import (
    FEATURE_NAMES as FEATURE_COLUMNS,
    LABEL_COLUMN,
)


def load_artifacts(script_dir):
    """
    Load the trained model and scaler from .pkl files.

    Args:
        script_dir (str): Directory containing the .pkl files.

    Returns:
        tuple: (model, scaler) loaded from flow_model.pkl and scaler.pkl.

    Raises:
        FileNotFoundError: If either .pkl file is missing.
    """
    model_path = os.path.join(script_dir, 'flow_model.pkl')
    scaler_path = os.path.join(script_dir, 'scaler.pkl')

    if not os.path.isfile(model_path):
        raise FileNotFoundError(
            f"Model file not found: {model_path}\n"
            f"Train the model first: python3 train_model.py"
        )

    if not os.path.isfile(scaler_path):
        raise FileNotFoundError(
            f"Scaler file not found: {scaler_path}\n"
            f"Train the model first: python3 train_model.py"
        )

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    print(f"  Model loaded:  {model_path}")
    print(f"  Scaler loaded: {scaler_path}")

    return model, scaler


def load_test_data(dataset_path):
    """
    Load the dataset and recreate the same test split used during training.

    Uses identical parameters to train_model.py (test_size=0.25,
    random_state=42, stratify=y) to ensure the ROC curve is evaluated
    on the exact same test set.

    Args:
        dataset_path (str): Path to the CSV dataset file.

    Returns:
        tuple: (X_test, y_test) as numpy arrays after scaling is applied
               by the caller.

    Raises:
        FileNotFoundError: If the dataset file does not exist.
    """
    if not os.path.isfile(dataset_path):
        raise FileNotFoundError(
            f"Dataset not found: {dataset_path}\n"
            f"Generate a dataset first:\n"
            f"  cd datasets && python3 generate_full_dataset.py"
        )

    # Load and clean dataset (same as train_model.py)
    df = pd.read_csv(dataset_path)
    df = df.dropna()
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], 0)

    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]

    # Recreate the same split used during training
    # random_state=42 and stratify=y guarantee identical split
    _, X_test, _, y_test = train_test_split(
        X, y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    print(f"  Dataset loaded: {dataset_path}")
    print(f"  Test set size:  {len(X_test)} flows")
    print(f"    Normal (0):   {(y_test == 0).sum()}")
    print(f"    Attack (1):   {(y_test == 1).sum()}")

    return X_test, y_test


def generate_roc_curve(model, scaler, X_test, y_test, output_path):
    """
    Generate and save the ROC curve visualization.

    Normalizes test features using the scaler, generates probability
    predictions, calculates the ROC curve (FPR vs TPR), and creates
    a publication-quality plot with AUC score.

    Args:
        model: Trained RandomForestClassifier.
        scaler: Fitted StandardScaler.
        X_test: Test feature matrix (DataFrame or array).
        y_test: Test labels (Series or array).
        output_path (str): File path to save the ROC curve image.
    """
    # Normalize test features using the same scaler from training
    X_test_scaled = scaler.transform(X_test)

    # Generate probability predictions for the positive class (attack)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

    # Calculate ROC curve points (False Positive Rate vs True Positive Rate)
    fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)

    # Calculate Area Under the Curve
    roc_auc = auc(fpr, tpr)

    print(f"\n  ROC AUC Score: {roc_auc:.4f}")

    # =========================================================================
    # Create the ROC curve plot
    # =========================================================================
    fig, ax = plt.subplots(figsize=(8, 6))

    # Plot the ROC curve
    ax.plot(
        fpr, tpr,
        color='#2196F3',
        linewidth=2.5,
        label=f'Random Forest (AUC = {roc_auc:.3f})'
    )

    # Plot the diagonal baseline (random classifier, AUC = 0.5)
    ax.plot(
        [0, 1], [0, 1],
        color='#9E9E9E',
        linewidth=1.5,
        linestyle='--',
        label='Random Classifier (AUC = 0.500)'
    )

    # Configure axes
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate (FPR)', fontsize=12)
    ax.set_ylabel('True Positive Rate (TPR)', fontsize=12)
    ax.set_title(
        'ROC Curve - DDoS Detection Model\n'
        'Random Forest Classifier',
        fontsize=14,
        fontweight='bold'
    )

    # Add legend
    ax.legend(loc='lower right', fontsize=11, framealpha=0.9)

    # Add grid for readability
    ax.grid(True, alpha=0.3, linestyle='-')

    # Add AUC annotation on the plot
    ax.annotate(
        f'AUC = {roc_auc:.4f}',
        xy=(0.5, 0.3),
        fontsize=16,
        fontweight='bold',
        color='#2196F3',
        ha='center'
    )

    # Tight layout and save
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close(fig)

    print(f"  ROC curve saved: {output_path}")
    file_size = os.path.getsize(output_path) / 1024
    print(f"  File size:       {file_size:.1f} KB")


def main():
    """
    Main entry point for ROC curve generation.

    Loads model artifacts and test data, generates probability predictions,
    and creates the ROC curve visualization.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Generate ROC curve for DDoS detection model'
    )
    parser.add_argument(
        '--dataset',
        type=str,
        default=None,
        help='Path to CSV dataset (default: ../datasets/flow_dataset.csv)'
    )
    args = parser.parse_args()

    # Resolve paths relative to this script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if args.dataset:
        dataset_path = args.dataset
    else:
        dataset_path = os.path.join(
            script_dir, '..', 'datasets', 'flow_dataset.csv'
        )

    output_path = os.path.join(script_dir, 'roc_curve.png')

    # Print banner
    print("\n" + "=" * 70)
    print("  ROC Curve Generator - DDoS Detection Model")
    print("=" * 70)

    try:
        # Step 1: Load trained model and scaler
        print("\n  Loading model artifacts...")
        model, scaler = load_artifacts(script_dir)

        # Step 2: Load and prepare test data
        print("\n  Loading test data...")
        X_test, y_test = load_test_data(dataset_path)

        # Step 3: Generate ROC curve
        print("\n  Generating ROC curve...")
        generate_roc_curve(model, scaler, X_test, y_test, output_path)

        # Done
        print("\n" + "=" * 70)
        print("  ROC curve generation complete!")
        print("=" * 70 + "\n")

    except FileNotFoundError as e:
        print(f"\n  ERROR: {e}")
        sys.exit(1)

    except Exception as e:
        print(f"\n  ERROR: Failed to generate ROC curve")
        print(f"  {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
