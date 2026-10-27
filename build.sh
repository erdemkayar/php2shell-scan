#!/bin/sh
# Builds the single-file package php2shell.pyz straight from the source tree (no committed copy to drift).
set -eu
cd "$(dirname "$0")"
python3 -m unittest -q tests.test_p2s
mkdir -p docs && cp p2s/guide.md docs/USER_GUIDE.md   # single source: the guide embedded in the package
T=$(mktemp -d)
cp -R p2s "$T/p2s"
cp php2shell_scan.py "$T/__main__.py"
find "$T" -name __pycache__ -type d -prune -exec rm -rf {} +
python3 -m zipapp "$T" -o php2shell.pyz -p "/usr/bin/env python3" -c
rm -rf "$T"
chmod +x php2shell.pyz
python3 php2shell.pyz --help >/dev/null
python3 php2shell.pyz --guide | head -1 | grep -q "User Guide"
echo "built php2shell.pyz ($(python3 -c 'import sys; sys.path.insert(0,"."); import p2s; print(p2s.__version__)'))"
