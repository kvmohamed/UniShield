# UniShield — Releasing

How a release is cut, and what is checked before it is published.

## Versioning

Semantic versioning: `MAJOR.MINOR.PATCH`. The version lives in
`pyproject.toml` (`project.version`), `src/unishield/__init__.py`
(`__version__`) and `configs/config.yaml` (`app.version`); change all three
together. A release that adds a database migration is at least a MINOR
release, and its notes say so.

## Before tagging

1. `main` is green in CI: the test matrix (Ubuntu and Windows: ruff F/E9,
   `pytest -W error::DeprecationWarning`, `scripts/verify_passive_mode.py`,
   `unishield-admin models verify`), the PostgreSQL job, the deploy-files
   job (`systemd-analyze verify`, `nginx -t`) and the supply-chain job
   (pip-audit on all three requirements files, CycloneDX SBOMs).
2. Dependency changes went through `pyproject.toml` and regenerated pins
   (README, "Updating dependencies"); new versions are a few weeks old
   unless they fix a vulnerability; pip-audit reports nothing.
3. If models ship with the release: train them, then
   `unishield-admin models verify` must report `ok` for every artifact. The
   SHA-256 in each `models/metadata/*.json` is what the registry checks on
   every load; never edit an artifact or its metadata by hand.
4. `unishield-admin db upgrade` from the previous release's database works
   (the migration tests cover an empty database, a pre-migration database
   and PostgreSQL; for a release with a new revision, also upgrade a copy of
   a real database).
5. The release notes list configuration changes, new environment
   variables and migrations.

## Tagging

Release tags are annotated, signed when a signing key is set up, and named
`vMAJOR.MINOR.PATCH` on a commit of `main`:

```bash
git switch main && git pull --ff-only
git tag -s v0.2.0 -m "UniShield 0.2.0"        # or -a when no signing key is configured
git push origin v0.2.0
```

Tags are never moved or reused; a broken release gets a new PATCH version.

## Release assets

Attach to the GitHub release:

- the source archive GitHub generates for the tag;
- the `sbom-cyclonedx` artifact of the tagged commit's CI run
  (`unishield-runtime.cdx.json`, `unishield-dev.cdx.json`);
- `SHA256SUMS` of every attached file, e.g.
  `sha256sum *.cdx.json > SHA256SUMS`;
- if models ship: the `models/saved/*.joblib` artifacts with their
  `models/metadata/*.json`; their checksums are already inside the metadata
  and are checked by `unishield-admin models verify` after download.

joblib artifacts are pickles and run code when loaded: install models only
from releases of this project, verified as above.
