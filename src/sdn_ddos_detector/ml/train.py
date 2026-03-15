#!/usr/bin/env python3
"""
Random Forest Model Training for DDoS Detection

Trains a Random Forest classifier on flow-based network traffic features
to distinguish normal traffic from DDoS attacks. Supports both synthetic
and real-world datasets (CIC-IDS2017, CIC-DDoS2019, UNSW-NB15).

The trained model and feature scaler are saved as .pkl files for use by
the Ryu SDN controller.

Usage:
    python -m sdn_ddos_detector.ml.train --dataset synthetic --split temporal
    python -m sdn_ddos_detector.ml.train --dataset cic-ids2017 --split temporal
    python -m sdn_ddos_detector.ml.train --dataset all --split both
    python -m sdn_ddos_detector.ml.train --cross-dataset
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sdn_ddos_detector.ml.feature_engineering import (
    CSV_HEADERS as EXPECTED_COLUMNS,
    EXPECTED_FEATURE_COUNT,
    FEATURE_NAMES as FEATURE_COLUMNS,
    LABEL_COLUMN,
)
from sdn_ddos_detector.ml.dataset_adapters import ADAPTER_REGISTRY

# Directory paths
SCRIPT_DIR = Path(__file__).resolve().parent
DATASETS_DIR = SCRIPT_DIR.parent / "datasets"
RESULTS_DIR = SCRIPT_DIR.parent.parent.parent / "results"

AVAILABLE_DATASETS = ["synthetic"] + list(ADAPTER_REGISTRY.keys())


def load_synthetic_dataset(filepath=None):
    """Load the synthetic flow dataset from CSV."""
    if filepath is None:
        filepath = DATASETS_DIR / "flow_dataset.csv"

    filepath = Path(filepath)
    if not filepath.is_file():
        raise FileNotFoundError(
            f"Synthetic dataset not found at: {filepath}\n"
            f"Generate one first:\n"
            f"  python -m sdn_ddos_detector.ml.generate_synthetic_dataset"
        )

    print(f"  Loading synthetic dataset: {filepath}")
    df = pd.read_csv(filepath)

    # Validate columns
    expected_col_count = EXPECTED_FEATURE_COUNT + 1
    if len(df.columns) != expected_col_count:
        raise ValueError(
            f"Expected {expected_col_count} columns, got {len(df.columns)}.\n"
            f"Expected: {EXPECTED_COLUMNS}\n"
            f"Got: {list(df.columns)}"
        )

    # Clean
    df = df.dropna()
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].replace([np.inf, -np.inf], 0)

    X = df[FEATURE_COLUMNS]
    y = df[LABEL_COLUMN]

    print(f"  Loaded {len(df)} flows ({(y == 0).sum()} normal, {(y == 1).sum()} attack)")
    return X, y, df


def load_real_dataset(dataset_name):
    """Load a real-world dataset using the appropriate adapter."""
    if dataset_name not in ADAPTER_REGISTRY:
        raise ValueError(
            f"Unknown dataset: {dataset_name}. "
            f"Available: {list(ADAPTER_REGISTRY.keys())}"
        )

    raw_dir = DATASETS_DIR / "raw" / dataset_name
    if not raw_dir.exists():
        raise FileNotFoundError(
            f"Dataset directory not found: {raw_dir}\n"
            f"Download the dataset first. See datasets/README.md for instructions."
        )

    adapter_cls = ADAPTER_REGISTRY[dataset_name]
    adapter = adapter_cls()

    print(f"  Loading {dataset_name} via {adapter_cls.__name__}...")
    mapped_df = adapter.load_and_map(str(raw_dir))

    X = mapped_df[FEATURE_COLUMNS]
    y = mapped_df[LABEL_COLUMN]

    print(f"  Loaded {len(mapped_df)} flows ({(y == 0).sum()} normal, {(y == 1).sum()} attack)")
    print(f"  Citation: {adapter.get_citation().split(chr(10))[0].strip()}")

    return X, y, mapped_df


def load_dataset(dataset_name, filepath=None):
    """Load dataset by name, dispatching to synthetic or real loader."""
    if dataset_name == "synthetic":
        return load_synthetic_dataset(filepath)
    else:
        return load_real_dataset(dataset_name)


def temporal_split(X, y, df, train_ratio=0.70):
    """Split data by temporal order: first train_ratio for training, rest for testing.

    Preserves temporal ordering — NO random shuffling across the time boundary.
    This prevents temporal leakage where future patterns inform past predictions.
    """
    split_idx = int(len(X) * train_ratio)
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]
    return X_train, X_test, y_train, y_test


def random_split(X, y):
    """Stratified random split (75/25)."""
    return train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)


def apply_balancing(X_train, y_train, method):
    """Apply class balancing to training data."""
    if method == "none" or method == "class-weight":
        # class-weight is handled in the model constructor
        return X_train, y_train

    if method == "undersample":
        # Random undersampling of majority class
        normal_idx = y_train[y_train == 0].index
        attack_idx = y_train[y_train == 1].index
        n_minority = min(len(normal_idx), len(attack_idx))
        if len(normal_idx) > len(attack_idx):
            sampled = normal_idx.to_series().sample(n=n_minority, random_state=42)
            keep_idx = sampled.index.union(attack_idx)
        else:
            sampled = attack_idx.to_series().sample(n=n_minority, random_state=42)
            keep_idx = normal_idx.union(sampled.index)
        return X_train.loc[keep_idx], y_train.loc[keep_idx]

    if method == "smote":
        try:
            from imblearn.over_sampling import SMOTE
            sm = SMOTE(random_state=42)
            X_res, y_res = sm.fit_resample(X_train, y_train)
            return X_res, y_res
        except ImportError:
            print("  WARNING: imbalanced-learn not installed. Falling back to class-weight.")
            return X_train, y_train

    return X_train, y_train


def train_model(X_train, y_train, balance_method="class-weight"):
    """Train a Random Forest classifier."""
    class_weight = "balanced" if balance_method == "class-weight" else None

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight=class_weight,
        random_state=42,
    )
    model.fit(X_train, y_train)
    return model


def evaluate_model(model, X_test, y_test, scaler=None):
    """Evaluate model and return metrics dictionary."""
    if scaler is not None:
        X_test_input = scaler.transform(X_test)
    else:
        X_test_input = X_test

    y_pred = model.predict(X_test_input)
    y_pred_proba = model.predict_proba(X_test_input)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "auc": roc_auc_score(y_test, y_pred_proba),
    }
    return metrics, y_pred, y_pred_proba


def save_results(dataset_name, split_method, metrics, y_test, y_pred,
                 y_pred_proba, model, scaler):
    """Save evaluation results to the results/ directory."""
    results_dir = RESULTS_DIR
    results_dir.mkdir(parents=True, exist_ok=True)

    prefix = f"{dataset_name}_{split_method}"

    # Classification report
    report = classification_report(
        y_test, y_pred, target_names=["Normal (0)", "Attack (1)"]
    )
    report_path = results_dir / f"{prefix}_classification_report.txt"
    report_path.write_text(report)

    # Per-attack breakdown (if multiclass labels available)
    breakdown_path = results_dir / f"{prefix}_per_attack_breakdown.csv"
    breakdown_data = {
        "metric": ["accuracy", "precision", "recall", "f1", "auc"],
        "value": [metrics["accuracy"], metrics["precision"], metrics["recall"],
                  metrics["f1"], metrics["auc"]],
    }
    pd.DataFrame(breakdown_data).to_csv(breakdown_path, index=False)

    print(f"  Results saved to {results_dir}/{prefix}_*")


def train_and_evaluate_single(dataset_name, split_method, balance_method,
                               filepath=None, save=True):
    """Full train/evaluate pipeline for a single dataset + split combination."""
    print(f"\n{'=' * 70}")
    print(f"  Dataset: {dataset_name} | Split: {split_method} | Balance: {balance_method}")
    print(f"{'=' * 70}")

    # Load data
    X, y, df = load_dataset(dataset_name, filepath)

    # Split
    if split_method == "temporal":
        X_train, X_test, y_train, y_test = temporal_split(X, y, df, train_ratio=0.70)
        print(f"  Split: TEMPORAL (first 70% train, last 30% test)")
    else:
        X_train, X_test, y_train, y_test = random_split(X, y)
        print(f"  Split: RANDOM stratified (75/25, random_state=42)")

    print(f"  Train: {len(X_train)} ({(y_train == 0).sum()} normal, {(y_train == 1).sum()} attack)")
    print(f"  Test:  {len(X_test)} ({(y_test == 0).sum()} normal, {(y_test == 1).sum()} attack)")

    # Balance
    X_train_bal, y_train_bal = apply_balancing(X_train, y_train, balance_method)

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_bal)
    X_test_scaled = scaler.transform(X_test)

    # Train
    print(f"  Training Random Forest (100 trees, max_depth=20)...")
    model = train_model(X_train_scaled, y_train_bal, balance_method)

    # Evaluate
    metrics, y_pred, y_pred_proba = evaluate_model(model, X_test, y_test, scaler)

    print(f"\n  Results:")
    print(f"    Accuracy:  {metrics['accuracy']:.4f}")
    print(f"    Precision: {metrics['precision']:.4f}")
    print(f"    Recall:    {metrics['recall']:.4f}")
    print(f"    F1:        {metrics['f1']:.4f}")
    print(f"    AUC:       {metrics['auc']:.4f}")

    # Save results
    if save:
        save_results(dataset_name, split_method, metrics, y_test, y_pred,
                     y_pred_proba, model, scaler)

    return model, scaler, metrics


def run_cross_dataset(split_method, balance_method):
    """Train on each dataset, test on all others. Produces transfer matrix."""
    print(f"\n{'=' * 70}")
    print(f"  Cross-Dataset Transfer Evaluation")
    print(f"{'=' * 70}")

    # Load all available datasets
    loaded = {}
    for name in AVAILABLE_DATASETS:
        try:
            X, y, df = load_dataset(name)
            loaded[name] = (X, y, df)
        except (FileNotFoundError, ValueError) as e:
            print(f"  Skipping {name}: {e}")

    if len(loaded) < 2:
        print("  Need at least 2 datasets for cross-dataset evaluation.")
        return

    results = []
    for train_name in loaded:
        X_train_full, y_train_full, _ = loaded[train_name]

        # Scale on training set
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train_full)

        # Train
        model = train_model(X_train_scaled, y_train_full, balance_method)

        for test_name in loaded:
            X_test_full, y_test_full, _ = loaded[test_name]
            X_test_scaled = scaler.transform(X_test_full)

            y_pred = model.predict(X_test_scaled)
            y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

            row = {
                "train_dataset": train_name,
                "test_dataset": test_name,
                "accuracy": accuracy_score(y_test_full, y_pred),
                "precision": precision_score(y_test_full, y_pred, zero_division=0),
                "recall": recall_score(y_test_full, y_pred, zero_division=0),
                "f1": f1_score(y_test_full, y_pred, zero_division=0),
                "auc": roc_auc_score(y_test_full, y_pred_proba),
            }
            results.append(row)
            marker = " (self)" if train_name == test_name else ""
            print(f"  Train={train_name} → Test={test_name}{marker}: "
                  f"F1={row['f1']:.4f}, AUC={row['auc']:.4f}")

    # Save
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    transfer_path = RESULTS_DIR / "cross_dataset_transfer.csv"
    pd.DataFrame(results).to_csv(transfer_path, index=False)
    print(f"\n  Transfer matrix saved to {transfer_path}")

    # Synthetic vs real comparison
    synth_rows = [r for r in results if r["train_dataset"] == "synthetic" and r["test_dataset"] != "synthetic"]
    real_rows = [r for r in results if r["train_dataset"] != "synthetic" and r["test_dataset"] == r["train_dataset"]]
    if synth_rows or real_rows:
        comparison = synth_rows + real_rows
        comp_path = RESULTS_DIR / "synthetic_vs_real_comparison.csv"
        pd.DataFrame(comparison).to_csv(comp_path, index=False)
        print(f"  Synthetic vs real comparison saved to {comp_path}")


def save_artifacts(model, scaler):
    """Save trained model and scaler to .pkl files with SHA-256 hashes."""
    print(f"\n{'=' * 70}")
    print(f"  Saving Model Artifacts")
    print(f"{'=' * 70}")

    model_path = SCRIPT_DIR / "flow_model.pkl"
    scaler_path = SCRIPT_DIR / "scaler.pkl"

    joblib.dump(model, model_path)
    model_size = model_path.stat().st_size / (1024 * 1024)
    print(f"  Model saved:  {model_path} ({model_size:.2f} MB)")

    joblib.dump(scaler, scaler_path)
    scaler_size = scaler_path.stat().st_size / 1024
    print(f"  Scaler saved: {scaler_path} ({scaler_size:.2f} KB)")

    # Verify
    joblib.load(model_path)
    joblib.load(scaler_path)
    print("  Verification: Both artifacts load successfully")

    # SHA-256 hashes
    hashes = {}
    for filename, fpath in [("flow_model.pkl", model_path), ("scaler.pkl", scaler_path)]:
        sha256 = hashlib.sha256()
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        hashes[filename] = sha256.hexdigest()
        print(f"    {filename}: {hashes[filename]}")

    hash_path = SCRIPT_DIR / "model_hashes.json"
    hash_path.write_text(json.dumps(hashes, indent=2))
    print(f"  Hash file saved: {hash_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Train Random Forest model for DDoS detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --dataset synthetic --split temporal
  %(prog)s --dataset cic-ids2017 --split temporal
  %(prog)s --dataset all --split both
  %(prog)s --cross-dataset
        """,
    )
    parser.add_argument(
        "--dataset",
        choices=AVAILABLE_DATASETS + ["all"],
        default="synthetic",
        help="Dataset to train on (default: synthetic)",
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default=None,
        help="Custom path to synthetic dataset CSV",
    )
    parser.add_argument(
        "--split",
        choices=["temporal", "random", "both"],
        default="temporal",
        help="Train/test split method (default: temporal)",
    )
    parser.add_argument(
        "--balance",
        choices=["smote", "undersample", "class-weight", "none"],
        default="class-weight",
        help="Class balancing method (default: class-weight)",
    )
    parser.add_argument(
        "--cross-dataset",
        action="store_true",
        help="Train on each dataset, test on all others",
    )
    parser.add_argument(
        "--save-model",
        action="store_true",
        help="Save model and scaler .pkl files (only for single dataset runs)",
    )
    args = parser.parse_args()

    print(f"\n{'=' * 70}")
    print(f"  DDoS Detection - Model Training Pipeline")
    print(f"{'=' * 70}")
    print(f"  Dataset:  {args.dataset}")
    print(f"  Split:    {args.split}")
    print(f"  Balance:  {args.balance}")

    if args.cross_dataset:
        run_cross_dataset(args.split, args.balance)
        return

    # Determine which datasets to run
    if args.dataset == "all":
        datasets = AVAILABLE_DATASETS
    else:
        datasets = [args.dataset]

    # Determine which splits to run
    if args.split == "both":
        splits = ["temporal", "random"]
    else:
        splits = [args.split]

    last_model = None
    last_scaler = None

    for ds in datasets:
        for sp in splits:
            try:
                model, scaler, metrics = train_and_evaluate_single(
                    ds, sp, args.balance,
                    filepath=args.dataset_path if ds == "synthetic" else None,
                )
                last_model = model
                last_scaler = scaler
            except (FileNotFoundError, ValueError) as e:
                print(f"\n  ERROR ({ds}/{sp}): {e}")

    # Save model artifacts if requested
    if args.save_model and last_model is not None:
        save_artifacts(last_model, last_scaler)

    print(f"\n{'=' * 70}")
    print(f"  Training complete!")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    main()
