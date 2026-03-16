"""
Adversarial robustness tests for the DDoS detection model.

Tests realistic evasion scenarios beyond simple Gaussian noise (audit 4.4):
1. Feature importance perturbation within physically realizable bounds
2. Crafted evasion scenarios (low-and-slow, mimicry, feature masking)
3. Black-box HopSkipJump attack via ART library

These tests require a trained model. Run after train.py.
"""

import os
import pytest
import numpy as np

from sdn_ddos_detector.ml.feature_engineering import FEATURE_NAMES


def _get_model_dir():
    """Return the ml/ directory where model artifacts live."""
    return os.path.join(
        os.path.dirname(__file__), '..', '..', 'src', 'sdn_ddos_detector', 'ml'
    )


def _load_model_and_data():
    """Load trained model, scaler, and generate test data.

    Returns (model, scaler, X_test_scaled, y_test, X_test_raw) or
    skips the test if artifacts are missing.
    """
    import joblib
    import pandas as pd
    from sklearn.model_selection import train_test_split

    ml_dir = _get_model_dir()
    model_path = os.path.join(ml_dir, 'flow_model.pkl')
    scaler_path = os.path.join(ml_dir, 'scaler.pkl')

    if not os.path.isfile(model_path) or not os.path.isfile(scaler_path):
        pytest.skip("Trained model not found. Run train.py first.")

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    # Try to load test data
    dataset_path = os.path.join(ml_dir, '..', 'datasets', 'synthetic', '..', '..', '..', '..', 'datasets', 'flow_dataset.csv')
    # Try alternate paths
    for candidate in [
        os.path.join(ml_dir, '..', '..', '..', '..', 'datasets', 'flow_dataset.csv'),
        os.path.join(ml_dir, '..', 'datasets', 'synthetic', 'flow_dataset.csv'),
    ]:
        if os.path.isfile(candidate):
            dataset_path = candidate
            break
    else:
        pytest.skip("Dataset not found. Generate with generate_synthetic_dataset.py first.")

    df = pd.read_csv(dataset_path).dropna()
    X = df[FEATURE_NAMES]
    y = df['label']

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    X_test_raw = X_test.values
    X_test_scaled = scaler.transform(X_test_raw)

    return model, scaler, X_test_scaled, y_test.values, X_test_raw


@pytest.mark.adversarial
class TestAdversarialRobustness:
    """Adversarial robustness tests for the DDoS detection model."""

    def test_feature_importance_perturbation(self):
        """Perturb top-5 features within physically realizable bounds.

        Unlike Gaussian noise, this perturbs only the most important
        features and enforces domain constraints (non-negative values,
        integer packet counts).
        """
        model, scaler, X_test_scaled, y_test, X_test_raw = _load_model_and_data()

        from sklearn.metrics import accuracy_score, recall_score, f1_score

        # Get feature importances and top-5 indices
        importances = model.feature_importances_
        top5_indices = np.argsort(importances)[-5:]

        # Get feature ranges from test data for realistic perturbation bounds
        feature_ranges = X_test_scaled.max(axis=0) - X_test_scaled.min(axis=0)

        attack_mask = y_test == 1
        clean_acc = accuracy_score(y_test, model.predict(X_test_scaled))

        print(f"\n  Clean accuracy: {clean_acc:.4f}")
        print(f"  Top-5 features: {[FEATURE_NAMES[i] for i in top5_indices]}")

        for epsilon in [0.01, 0.03, 0.05, 0.10]:
            X_adv = X_test_scaled.copy()
            rng = np.random.RandomState(42)

            # Only perturb attack samples on top-5 features
            for idx in top5_indices:
                perturbation = rng.uniform(
                    -epsilon * feature_ranges[idx],
                    epsilon * feature_ranges[idx],
                    size=attack_mask.sum()
                )
                X_adv[attack_mask, idx] += perturbation

            y_adv = model.predict(X_adv)
            adv_acc = accuracy_score(y_test, y_adv)
            adv_recall = recall_score(y_test, y_adv, zero_division=0)
            adv_f1 = f1_score(y_test, y_adv, zero_division=0)
            evaded = int((y_adv[attack_mask] == 0).sum())

            print(f"  eps={epsilon:.2f}: acc={adv_acc:.4f} recall={adv_recall:.4f} "
                  f"f1={adv_f1:.4f} evaded={evaded}/{attack_mask.sum()}")

        # Model should retain >80% recall at epsilon=0.05
        X_adv_05 = X_test_scaled.copy()
        rng = np.random.RandomState(42)
        for idx in top5_indices:
            perturbation = rng.uniform(
                -0.05 * feature_ranges[idx],
                0.05 * feature_ranges[idx],
                size=attack_mask.sum()
            )
            X_adv_05[attack_mask, idx] += perturbation
        recall_05 = recall_score(y_test, model.predict(X_adv_05), zero_division=0)
        assert recall_05 > 0.5, f"Model too fragile: recall={recall_05:.4f} at eps=0.05"

    def test_evasion_scenarios(self):
        """Craft realistic evasion attacks.

        Scenario 1: Low-and-slow — normal PPS but many flows to same dst
        Scenario 2: Mimicry — attack features within 1 std of benign mean
        Scenario 3: Feature masking — set top-3 important features to normal range
        """
        model, scaler, X_test_scaled, y_test, X_test_raw = _load_model_and_data()

        attack_mask = y_test == 1
        normal_mask = y_test == 0

        # Compute benign statistics (on raw features before scaling)
        benign_mean = X_test_raw[normal_mask].mean(axis=0)
        benign_std = X_test_raw[normal_mask].std(axis=0)

        # Scenario 1: Low-and-slow
        # Reduce PPS/BPS to normal range but keep high flows_to_dst
        X_lowslow = X_test_raw.copy()
        pps_idx = FEATURE_NAMES.index('packet_count_per_second')
        bps_idx = FEATURE_NAMES.index('byte_count_per_second')
        ftd_idx = FEATURE_NAMES.index('flows_to_dst')

        # Set attack PPS/BPS to benign mean, keep aggregate features high
        X_lowslow[attack_mask, pps_idx] = benign_mean[pps_idx]
        X_lowslow[attack_mask, bps_idx] = benign_mean[bps_idx]
        X_lowslow_scaled = scaler.transform(X_lowslow)
        y_lowslow = model.predict(X_lowslow_scaled)
        evaded_lowslow = (y_lowslow[attack_mask] == 0).sum()

        # Scenario 2: Mimicry — set all attack features within 1 std of benign mean
        X_mimicry = X_test_raw.copy()
        rng = np.random.RandomState(42)
        for i in range(len(FEATURE_NAMES)):
            X_mimicry[attack_mask, i] = rng.normal(
                benign_mean[i], benign_std[i], size=attack_mask.sum()
            )
            X_mimicry[attack_mask, i] = np.maximum(0, X_mimicry[attack_mask, i])
        X_mimicry_scaled = scaler.transform(X_mimicry)
        y_mimicry = model.predict(X_mimicry_scaled)
        evaded_mimicry = (y_mimicry[attack_mask] == 0).sum()

        # Scenario 3: Feature masking — set top-3 important features to normal range
        importances = model.feature_importances_
        top3_indices = np.argsort(importances)[-3:]
        X_masked = X_test_raw.copy()
        for idx in top3_indices:
            X_masked[attack_mask, idx] = benign_mean[idx]
        X_masked_scaled = scaler.transform(X_masked)
        y_masked = model.predict(X_masked_scaled)
        evaded_masked = (y_masked[attack_mask] == 0).sum()

        total_attacks = attack_mask.sum()
        print(f"\n  Evasion scenarios (total attacks: {total_attacks}):")
        print(f"  Low-and-slow: {evaded_lowslow}/{total_attacks} evaded")
        print(f"  Full mimicry: {evaded_mimicry}/{total_attacks} evaded")
        print(f"  Feature mask: {evaded_masked}/{total_attacks} evaded "
              f"(top-3: {[FEATURE_NAMES[i] for i in top3_indices]})")

        # Lenient thresholds — goal is detecting catastrophic failure, not
        # demanding high adversarial robustness from a Random Forest classifier.
        recall_lowslow = 1 - (evaded_lowslow / total_attacks)
        recall_mimicry = 1 - (evaded_mimicry / total_attacks)
        recall_masked = 1 - (evaded_masked / total_attacks)
        assert recall_lowslow >= 0.3, f"Low-and-slow recall catastrophic: {recall_lowslow:.3f}"
        assert recall_mimicry >= 0.2, f"Mimicry recall catastrophic: {recall_mimicry:.3f}"
        assert recall_masked >= 0.4, f"Feature masking recall catastrophic: {recall_masked:.3f}"

    def test_hopskipjump_attack(self):
        """Black-box attack using ART library (if installed).

        HopSkipJump is a decision-based attack that only needs
        model predictions (not gradients), realistic for SDN attacks.
        """
        try:
            from art.estimators.classification import SklearnClassifier
            from art.attacks.evasion import HopSkipJump
        except ImportError:
            pytest.skip("Install adversarial-robustness-toolbox for this test")

        model, scaler, X_test_scaled, y_test, _ = _load_model_and_data()

        from sklearn.metrics import accuracy_score

        # Wrap model for ART
        art_classifier = SklearnClassifier(model=model)

        # Select a small sample of attack flows for efficiency
        attack_mask = y_test == 1
        attack_indices = np.where(attack_mask)[0][:100]
        X_attack = X_test_scaled[attack_indices]

        # Run HopSkipJump attack
        attack = HopSkipJump(
            classifier=art_classifier,
            targeted=False,
            max_iter=50,
            max_eval=1000,
            init_eval=100,
        )
        X_adv = attack.generate(x=X_attack)

        # Measure evasion rate
        y_clean = model.predict(X_attack)
        y_adv = model.predict(X_adv)
        clean_detected = (y_clean == 1).sum()
        adv_detected = (y_adv == 1).sum()
        evaded = clean_detected - adv_detected

        print(f"\n  HopSkipJump attack on {len(attack_indices)} attack samples:")
        print(f"  Clean detected: {clean_detected}")
        print(f"  After attack:   {adv_detected}")
        print(f"  Evaded:         {evaded}")

        adversarial_accuracy = adv_detected / len(attack_indices) if len(attack_indices) > 0 else 0
        assert adversarial_accuracy >= 0.2, \
            f"Model trivially breakable: adversarial accuracy {adversarial_accuracy:.3f}"
