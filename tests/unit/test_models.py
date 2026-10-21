"""Unit tests for the models package: features, dataset, calibration, registry, training, ML detector."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from unishield.data.sample_generator import SimulatedReader, build_scenario
from unishield.detectors.ml_detector import MLDetector, likely_entities
from unishield.evaluation.metrics import binary_metrics, episode_metrics, episodes
from unishield.models.calibration import IsotonicCalibrator, brier_score, expected_calibration_error
from unishield.models.dataset import (
    BENIGN,
    WindowRecord,
    load_windows,
    normalise_label,
    save_windows,
    synthetic_windows,
    window_label,
)
from unishield.models.features import FEATURE_GROUPS, MODEL_FEATURE_KEYS, keys_without, model_vector
from unishield.models.predict import WindowModel
from unishield.models.registry import ModelIntegrityError, ModelRegistry
from unishield.models.train import split_by_run, train_bundle
from unishield.processing.pipeline import Pipeline, default_detectors
from unishield.schemas.alert import ThreatClass
from unishield.schemas.flow import NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCENARIOS = ["benign_hard", "port_scan", "ddos_syn", "dga"]


@pytest.fixture(scope="module")
def windows():
    return synthetic_windows(SCENARIOS, range(1, 7))


@pytest.fixture(scope="module")
def splits(windows):
    return split_by_run(windows, (0.5, 0.25, 0.25), seed=3)


@pytest.fixture(scope="module")
def rf_bundle(splits):
    train, cal, _ = splits
    return train_bundle("random_forest", train, cal, MODEL_FEATURE_KEYS, seed=1)


# --- features ---------------------------------------------------------------

def test_feature_keys_are_unique_and_grouped():
    assert len(MODEL_FEATURE_KEYS) == len(set(MODEL_FEATURE_KEYS))
    assert set(keys_without(["tls"])) == set(MODEL_FEATURE_KEYS) - set(FEATURE_GROUPS["tls"])
    with pytest.raises(ValueError):
        keys_without(["nope"])


def test_model_vector_handles_missing_and_bad_values():
    vec = model_vector({"total_flows": 9, "tcp_ratio": "x", "bytes_per_second": float("nan"),
                        "exfil_candidates": [{"upload_bytes": 99, "robust_z": None}]})
    as_dict = dict(zip(MODEL_FEATURE_KEYS, vec))
    assert as_dict["total_flows"] == pytest.approx(np.log1p(9))
    assert as_dict["tcp_ratio"] == 0 and as_dict["bytes_per_second"] == 0
    assert as_dict["max_pair_upload"] == pytest.approx(np.log1p(99))
    assert as_dict["max_upload_robust_z"] == 0


# --- labels and dataset -----------------------------------------------------

@pytest.mark.parametrize("label,expected", [
    ("BENIGN", BENIGN), ("Benign", BENIGN), ("DDoS", "DDOS_VOLUMETRIC"), ("PortScan", "PORT_SCAN"),
    ("DDOS_SYN_FLOOD", "SYN_FLOOD"), ("DGA", "DGA_DETECTED"), ("C2_BEACONING", "C2_BEACONING"),
    ("flow=From-Botnet-V42-TCP", "C2_BEACONING"), ("flow=Background-UDP", BENIGN),
    ("Web Attack Brute Force", "ATTACK"), (None, None), ("  ", None),
])
def test_normalise_label(label, expected):
    assert normalise_label(label) == expected


def test_window_label_majority_attack():
    def flow(label):
        return NormalisedFlow(timestamp=T0, source_ip="10.0.0.1", destination_ip="10.0.0.2",
                              protocol=ProtocolType.TCP, label=label)
    assert window_label([flow("BENIGN"), flow(None)]) == (BENIGN, 0)
    assert window_label([flow("PORT_SCAN"), flow("PORT_SCAN"), flow("DGA"), flow("BENIGN")]) == ("PORT_SCAN", 3)


def test_synthetic_windows_record_rule_outcomes(windows):
    scan = [w for w in windows if w.run == "port_scan:1"]
    assert any(w.label == "PORT_SCAN" for w in scan)
    assert any("PORT_SCAN" in w.rule_classes for w in scan if w.label == "PORT_SCAN")
    assert not any(w.rule_classes for w in windows if w.run.startswith("benign_hard"))
    assert all(len(w.features) == len(MODEL_FEATURE_KEYS) for w in windows)


def test_dataset_csv_roundtrip(windows, tmp_path):
    path = tmp_path / "w.csv"
    sha = save_windows(windows[:50], path)
    loaded, keys = load_windows(path)
    assert len(sha) == 64 and keys == MODEL_FEATURE_KEYS
    assert [w.label for w in loaded] == [w.label for w in windows[:50]]
    assert loaded[3].rule_classes == windows[3].rule_classes
    assert loaded[3].features == pytest.approx(windows[3].features, rel=1e-5)


def test_load_rejects_foreign_csv(tmp_path):
    path = tmp_path / "x.csv"
    path.write_text("a,b\n1,2\n")
    with pytest.raises(ValueError):
        load_windows(path)


def test_split_by_run_has_no_shared_runs(splits):
    runs = [{w.run for w in part} for part in splits]
    assert not (runs[0] & runs[1]) and not (runs[0] & runs[2]) and not (runs[1] & runs[2])
    for part in splits:                                   # stratified: every part sees attacks
        assert any(w.is_attack for w in part)


# --- calibration ------------------------------------------------------------

def test_isotonic_calibration_is_monotone_and_serialisable():
    rng = np.random.default_rng(0)
    scores = rng.uniform(0, 1, 2000)
    labels = (rng.uniform(0, 1, 2000) < scores ** 2).astype(int)
    cal = IsotonicCalibrator.fit(scores, labels)
    out = cal(np.linspace(0, 1, 50))
    assert np.all(np.diff(out) >= 0) and out.min() >= 0 and out.max() <= 1
    again = IsotonicCalibrator.from_dict(json.loads(json.dumps(cal.to_dict())))
    assert np.array_equal(again(scores), cal(scores))
    assert expected_calibration_error(cal(scores), labels) < expected_calibration_error(scores, labels)


def test_calibration_needs_both_classes():
    with pytest.raises(ValueError):
        IsotonicCalibrator.fit([0.1, 0.2], [0, 0])


def test_brier_and_ece_perfect_predictions():
    assert brier_score([0, 1], [0, 1]) == 0
    assert expected_calibration_error([0, 1], [0, 1]) == 0


# --- training and inference -------------------------------------------------

def test_random_forest_is_calibrated_and_separates_test_windows(rf_bundle, splits):
    model = WindowModel(rf_bundle)
    assert model.calibrated and BENIGN in rf_bundle["classes"]
    test = splits[2]
    _, prob = model.scores(np.asarray([w.features for w in test]))
    y = np.asarray([int(w.is_attack) for w in test])
    m = binary_metrics(y, (prob >= 0.9).astype(int))
    assert m["precision"] >= 0.9 and m["recall"] >= 0.5


def test_isolation_forest_bundle_scores_without_classes(splits):
    bundle = train_bundle("isolation_forest", splits[0], splits[1], MODEL_FEATURE_KEYS)
    assert bundle["kind"] == "unsupervised" and bundle["classes"] == []
    prediction = WindowModel(bundle).predict({"total_flows": 3})
    assert prediction.predicted_class is None and prediction.raw_score > 0


def test_unknown_algorithm_rejected(splits):
    with pytest.raises(ValueError):
        train_bundle("svm", splits[0], splits[1], MODEL_FEATURE_KEYS)


# --- registry ---------------------------------------------------------------

def test_registry_versions_and_integrity(rf_bundle, tmp_path):
    reg = ModelRegistry(tmp_path / "saved", tmp_path / "meta")
    first = reg.save("window_rf", rf_bundle, {"algorithm": "random_forest"})
    second = reg.save("window_rf", rf_bundle, {"algorithm": "random_forest"})
    assert (first["version"], second["version"]) == (1, 2) and reg.versions("window_rf") == [1, 2]
    bundle, meta = reg.load("window_rf")
    assert meta["version"] == 2 and len(meta["sha256"]) == 64 and "scikit-learn" in meta["libraries"]
    assert bundle["algorithm"] == "random_forest"

    artifact = tmp_path / "saved" / "window_rf-v2.joblib"
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(ModelIntegrityError):
        reg.load("window_rf")
    assert reg.load("window_rf", version=1)[1]["version"] == 1


@pytest.mark.parametrize("name", ["../evil", "Window", "a/b", "", "x" * 65])
def test_registry_rejects_unsafe_names(name, tmp_path):
    reg = ModelRegistry(tmp_path / "s", tmp_path / "m")
    with pytest.raises(ValueError):
        reg.save(name, {}, {})


def test_registry_missing_model(tmp_path):
    reg = ModelRegistry(tmp_path / "s", tmp_path / "m")
    assert reg.metadata("window_rf") is None and reg.list() == []
    with pytest.raises(FileNotFoundError):
        reg.load("window_rf")


# --- ML detector and detection modes ----------------------------------------

def test_ml_detector_alerts_only_on_unexplained_windows(rf_bundle):
    detector = MLDetector(WindowModel(rf_bundle), threshold=0.5)
    sc = build_scenario("port_scan", 42)
    seen = []
    Pipeline(window_observer=lambda w, f, a, r: seen.append((w, f))).run(SimulatedReader(sc.flows))
    scan_window, features = max(seen, key=lambda wf: wf[1].get("max_vertical_ports", 0))
    alerts = detector.detect(scan_window.records, features, scan_window.start, scan_window.end)
    assert alerts and alerts[0].threat_class == ThreatClass.PORT_SCAN
    assert alerts[0].confidence >= 0.5
    assert alerts[0].evidence["calibrated_probability"] == alerts[0].confidence
    explained = dict(features, rule_alert_classes=["PORT_SCAN"])
    assert detector.detect(scan_window.records, explained, scan_window.start, scan_window.end) == []


def test_uncalibrated_model_never_alerts(rf_bundle):
    detector = MLDetector(WindowModel(dict(rf_bundle, calibrator=None)), threshold=0.01)
    flow = NormalisedFlow(timestamp=T0, source_ip="10.0.0.1", destination_ip="10.0.0.2",
                          protocol=ProtocolType.TCP)
    assert detector.detect([flow], {"total_flows": 1}, T0, T0 + timedelta(seconds=10)) == []


def test_likely_entities():
    assert likely_entities(ThreatClass.PORT_SCAN, {"top_scanner_ip": "1.2.3.4"}) == ("1.2.3.4", None)
    assert likely_entities(ThreatClass.DATA_EXFILTRATION,
                           {"exfil_candidates": [{"source_ip": "a", "destination_ip": "b"}]}) == ("a", "b")
    assert likely_entities(ThreatClass.DNS_TUNNELLING, {"tunnel_candidates": [{"clients": ["c"]}]}) == ("c", None)
    assert likely_entities(ThreatClass.STATISTICAL_ANOMALY, {}) == (None, None)


def test_detection_modes(monkeypatch):
    names = {d.name for d in default_detectors("rules")}
    assert "ml_detector" not in names and "dns_detector" in names
    with pytest.raises(ValueError):
        default_detectors("magic")
    monkeypatch.setattr(MLDetector, "from_registry", classmethod(lambda cls, **kw: None))
    assert {d.name for d in default_detectors("hybrid")} == names          # falls back to rules
    with pytest.raises(RuntimeError):
        default_detectors("ml")


def test_hybrid_mode_appends_ml_detector(monkeypatch, rf_bundle):
    monkeypatch.setattr(MLDetector, "from_registry",
                        classmethod(lambda cls, **kw: cls(WindowModel(rf_bundle), **kw)))
    hybrid = default_detectors("hybrid")
    assert hybrid[-1].name == "ml_detector" and hybrid[-1].require_unexplained
    (ml,) = default_detectors("ml")
    assert not ml.require_unexplained


# --- metrics ----------------------------------------------------------------

def _rec(run, label, start):
    return WindowRecord(run=run, window_start=T0 + timedelta(seconds=start),
                        window_end=T0 + timedelta(seconds=start + 10), features=[], label=label,
                        flow_count=1, attack_flows=int(label != BENIGN))


def test_binary_metrics():
    m = binary_metrics([1, 1, 0, 0], [1, 0, 1, 0])
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 1, 1)
    assert m["precision"] == m["recall"] == m["f1"] == m["false_positive_rate"] == 0.5


def test_episodes_split_on_gaps_and_delay():
    recs = [_rec("r", "PORT_SCAN", 0), _rec("r", "PORT_SCAN", 5), _rec("r", BENIGN, 10),
            _rec("r", "PORT_SCAN", 1000), _rec("r", "PORT_SCAN", 1005)]
    assert [len(e.indices) for e in episodes(recs)] == [2, 2]
    m = episode_metrics(recs, [0, 1, 0, 0, 0])
    assert m["episodes"] == 2 and m["episodes_detected"] == 1 and m["delay_median_sec"] == 5.0
