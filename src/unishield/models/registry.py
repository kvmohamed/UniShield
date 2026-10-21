"""
UniShield — Model Registry

Stores trained window models as versioned artifacts:

    models/saved/<name>-v<N>.joblib      the model bundle
    models/metadata/<name>-v<N>.json     algorithm, feature keys, training data
                                         hash, metrics, library versions and the
                                         artifact's SHA-256

``load`` refuses an artifact whose SHA-256 no longer matches its metadata.
joblib files are pickles and can execute code when loaded: only load
artifacts this installation trained. Names are restricted to
``[a-z0-9_]`` so they cannot escape the model directories.
"""

from __future__ import annotations

import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import joblib

from unishield.config import get_config
from unishield.models.dataset import file_sha256

_NAME = re.compile(r"^[a-z0-9_]{1,64}$")
_ARTIFACT = re.compile(r"^(?P<name>[a-z0-9_]{1,64})-v(?P<version>\d+)\.json$")


class ModelIntegrityError(RuntimeError):
    """The artifact on disk does not match the hash recorded at training time."""


def _library_versions() -> dict[str, str]:
    import numpy
    import sklearn

    versions = {"python": platform.python_version(), "numpy": numpy.__version__,
                "scikit-learn": sklearn.__version__, "joblib": joblib.__version__}
    try:
        import xgboost

        versions["xgboost"] = xgboost.__version__
    except ImportError:
        pass
    return versions


class ModelRegistry:
    """Versioned, hash-checked storage for model bundles."""

    def __init__(self, saved_dir: Path | str | None = None, metadata_dir: Path | str | None = None):
        cfg = get_config().models
        self.saved_dir = Path(saved_dir or cfg.saved_dir)
        self.metadata_dir = Path(metadata_dir or cfg.metadata_dir)

    @staticmethod
    def _check_name(name: str) -> str:
        if not _NAME.match(name or ""):
            raise ValueError(f"Invalid model name {name!r}: use 1-64 characters a-z, 0-9, _")
        return name

    def _paths(self, name: str, version: int) -> tuple[Path, Path]:
        stem = f"{name}-v{int(version)}"
        return self.saved_dir / f"{stem}.joblib", self.metadata_dir / f"{stem}.json"

    def versions(self, name: str) -> list[int]:
        self._check_name(name)
        if not self.metadata_dir.is_dir():
            return []
        found = []
        for p in self.metadata_dir.glob(f"{name}-v*.json"):
            m = _ARTIFACT.match(p.name)
            if m and m["name"] == name:
                found.append(int(m["version"]))
        return sorted(found)

    def save(self, name: str, bundle: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
        """Store ``bundle`` as the next version of ``name``; returns the written metadata."""
        self._check_name(name)
        version = (self.versions(name) or [0])[-1] + 1
        artifact, meta_path = self._paths(name, version)
        self.saved_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(bundle, artifact)
        meta = dict(metadata)
        meta.update(
            name=name,
            version=version,
            artifact=artifact.name,
            sha256=file_sha256(artifact),
            created_at=datetime.now(timezone.utc).isoformat(),
            libraries=_library_versions(),
        )
        meta_path.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        return meta

    def metadata(self, name: str, version: Optional[int] = None) -> Optional[dict[str, Any]]:
        """Metadata of ``version`` (latest if omitted), or None if there is none."""
        versions = self.versions(name)
        if not versions:
            return None
        version = versions[-1] if version is None else int(version)
        if version not in versions:
            return None
        return json.loads(self._paths(name, version)[1].read_text(encoding="utf-8"))

    def load(self, name: str, version: Optional[int] = None) -> tuple[dict[str, Any], dict[str, Any]]:
        """(bundle, metadata) after checking the artifact's SHA-256."""
        meta = self.metadata(name, version)
        if meta is None:
            raise FileNotFoundError(f"No saved model named {name!r}" + (f" v{version}" if version else ""))
        artifact = self._paths(name, meta["version"])[0]
        if not artifact.is_file():
            raise FileNotFoundError(f"Model artifact missing: {artifact}")
        if file_sha256(artifact) != meta["sha256"]:
            raise ModelIntegrityError(f"{artifact} does not match the SHA-256 recorded at training time")
        return joblib.load(artifact), meta

    def list(self) -> list[dict[str, Any]]:
        """Metadata of every stored model version."""
        if not self.metadata_dir.is_dir():
            return []
        out = []
        for p in sorted(self.metadata_dir.glob("*-v*.json")):
            if _ARTIFACT.match(p.name):
                out.append(json.loads(p.read_text(encoding="utf-8")))
        return out
