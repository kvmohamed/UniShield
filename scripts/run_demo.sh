#!/usr/bin/env sh
# ================================================================
# UniShield - one-command offline demo (Linux / macOS)
#
#   scripts/run_demo.sh            full demo (several minutes)
#   scripts/run_demo.sh --quick    shorter demo (about a minute)
#   scripts/run_demo.sh --serve    then start the dashboard
#
# All data is synthetic or written locally. Nothing is sent on any network.
# ================================================================
set -e
cd "$(dirname "$0")/.."

PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python

exec "$PY" scripts/run_demo.py "$@"
