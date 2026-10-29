"""
UniShield — Window Dataset

Builds labelled window-level datasets by running the real pipeline over
labelled flows and recording, for every analysed window:

    - the model feature vector (``models.features``)
    - the window label: the most common attack label among its flows, or
      BENIGN when it holds no attack flow
    - which classes the rule stage raised or suppressed, and which classes
      the post-rule detectors (statistical, Isolation Forest) raised

so that supervised models, unsupervised models, rules and hybrids can be
trained and compared on exactly the windows the pipeline analyses.

Labels come from the generator (synthetic scenarios) or from a ``label``
column in labelled public datasets (e.g. CICIDS2017 flow CSVs, mapped by
``normalise_label``). Labels are used only for training and evaluation;
detectors never see them.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from unishield.models.features import MODEL_FEATURE_KEYS, model_vector
from unishield.schemas.flow import NormalisedFlow

BENIGN = "BENIGN"

# Generator and public-dataset labels → UniShield threat class names
_LABEL_MAP = {
    "BENIGN": BENIGN, "NORMAL": BENIGN, "BACKGROUND": BENIGN,
    "DDOS_SYN_FLOOD": "SYN_FLOOD", "DDOS_UDP_FLOOD": "UDP_FLOOD",
    "DGA": "DGA_DETECTED",
    # CICIDS2017 / CSE-CIC-IDS2018 style labels
    "DDOS": "DDOS_VOLUMETRIC", "DOS HULK": "DDOS_PROTOCOL", "DOS GOLDENEYE": "DDOS_PROTOCOL",
    "DOS SLOWLORIS": "DDOS_PROTOCOL", "DOS SLOWHTTPTEST": "DDOS_PROTOCOL",
    "PORTSCAN": "PORT_SCAN", "BOT": "C2_BEACONING", "INFILTRATION": "DATA_EXFILTRATION",
    "FTP-PATATOR": "BRUTE_FORCE", "SSH-PATATOR": "BRUTE_FORCE",
    # CTU-13 style: botnet traffic mixes C2, spam, scans and floods, so it keeps its own label
    "BOTNET": "BOTNET",
}
_THREAT_NAMES = {
    "DDOS_VOLUMETRIC", "DDOS_PROTOCOL", "SYN_FLOOD", "UDP_FLOOD", "PORT_SCAN", "HOST_SCAN",
    "RECONNAISSANCE", "C2_BEACONING", "DATA_EXFILTRATION", "DNS_TUNNELLING", "DGA_DETECTED",
    "ENCRYPTED_SESSION_ANOMALY", "BRUTE_FORCE", "SPAM_ACTIVITY",
}


def normalise_label(label: Optional[str]) -> Optional[str]:
    """Map a dataset label to BENIGN, a threat class name, or ATTACK (unknown attack label)."""
    if label is None or not str(label).strip():
        return None
    text = " ".join(str(label).strip().upper().split())
    if text in _LABEL_MAP:
        return _LABEL_MAP[text]
    if text in _THREAT_NAMES:
        return text
    if text.startswith("FLOW="):                      # CTU-13 binetflow labels
        if "BOTNET" in text:
            return "BOTNET"
        if "NORMAL" in text or "BACKGROUND" in text:
            return BENIGN
    return "ATTACK"


@dataclass
class WindowRecord:
    """One analysed window with its label and what each detector stage concluded."""
    run: str
    window_start: datetime
    window_end: datetime
    features: list[float]
    label: str
    flow_count: int
    attack_flows: int
    rule_classes: list[str] = field(default_factory=list)
    post_rule_classes: list[str] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.label != BENIGN


def window_label(flows: Iterable[NormalisedFlow]) -> tuple[str, int]:
    """(label, attack flow count) of a window; unlabelled flows count as benign."""
    counts = Counter()
    for f in flows:
        label = normalise_label(f.label)
        if label is not None and label != BENIGN:
            counts[label] += 1
    if not counts:
        return BENIGN, 0
    return counts.most_common(1)[0][0], sum(counts.values())


class WindowRecorder:
    """Pipeline ``window_observer`` that collects WindowRecords."""

    def __init__(self, run: str, feature_keys: list[str] = MODEL_FEATURE_KEYS):
        self.run = run
        self.feature_keys = feature_keys
        self.records: list[WindowRecord] = []

    def __call__(self, window, features, alerts, rule_classes) -> None:
        label, attack_flows = window_label(window.records)
        post = sorted({a.threat_class.value for a in alerts} - set(rule_classes))
        self.records.append(WindowRecord(
            run=self.run,
            window_start=window.start,
            window_end=window.end,
            features=model_vector(features, self.feature_keys),
            label=label,
            flow_count=len(window.records),
            attack_flows=attack_flows,
            rule_classes=sorted(rule_classes),
            post_rule_classes=post,
        ))


def windows_from_reader(reader, run: str, **pipeline_kwargs) -> list[WindowRecord]:
    """Run a fresh rules-mode pipeline over ``reader`` and return its labelled windows."""
    from unishield.processing.pipeline import Pipeline

    recorder = WindowRecorder(run)
    pipeline_kwargs.setdefault("detection_mode", "rules")
    Pipeline(window_observer=recorder, **pipeline_kwargs).run(reader)
    return recorder.records


def synthetic_windows(scenarios: Iterable[str], seeds: Iterable[int]) -> list[WindowRecord]:
    """Labelled windows for every (scenario, seed) of the seeded generator."""
    from unishield.data.sample_generator import SimulatedReader, build_scenario

    records: list[WindowRecord] = []
    for name in scenarios:
        for seed in seeds:
            scenario = build_scenario(name, seed)
            records += windows_from_reader(SimulatedReader(scenario.flows), run=f"{name}:{seed}")
    return records


# ---------------------------------------------------------------------------
# CSV persistence
# ---------------------------------------------------------------------------

_META = ["run", "window_start", "window_end", "label", "flow_count", "attack_flows",
         "rule_classes", "post_rule_classes"]


def save_windows(records: list[WindowRecord], path: Path | str,
                 feature_keys: list[str] = MODEL_FEATURE_KEYS) -> str:
    """Write windows to CSV; returns the SHA-256 of the written file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(_META + feature_keys)
        for r in records:
            writer.writerow([
                r.run, r.window_start.isoformat(), r.window_end.isoformat(), r.label, r.flow_count,
                r.attack_flows, json.dumps(r.rule_classes), json.dumps(r.post_rule_classes),
            ] + [f"{v:.6g}" for v in r.features])
    return file_sha256(path)


def load_windows(path: Path | str) -> tuple[list[WindowRecord], list[str]]:
    """Read windows written by ``save_windows``; returns (records, feature keys)."""
    with Path(path).open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        if header[:len(_META)] != _META:
            raise ValueError(f"{path} is not a UniShield window dataset")
        keys = header[len(_META):]
        records = []
        for row in reader:
            records.append(WindowRecord(
                run=row[0],
                window_start=datetime.fromisoformat(row[1]),
                window_end=datetime.fromisoformat(row[2]),
                label=row[3],
                flow_count=int(row[4]),
                attack_flows=int(row[5]),
                rule_classes=json.loads(row[6]),
                post_rule_classes=json.loads(row[7]),
                features=[float(v) for v in row[len(_META):]],
            ))
    return records, keys


def file_sha256(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
