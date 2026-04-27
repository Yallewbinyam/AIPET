#!/usr/bin/env bash
# =============================================================
# AIPET X -- Windows installer zip build
#
# Produces agent/packaging/aipet-agent-windows-<VERSION>_all.zip
# from agent/packaging/windows/ + agent/aipet_agent.py + agent/watchdog.py.
# Records a SHA256 digest beside the artifact.
#
# Reproducible-ish: every file inside the zip has a fixed timestamp
# (epoch 0) so two builds from the same source tree produce the same
# digest. Useful for change attestation in the verification report.
# =============================================================
set -euo pipefail

VERSION="${VERSION:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIN_DIR="$SCRIPT_DIR/windows"
OUT_FILE="$SCRIPT_DIR/aipet-agent-windows-${VERSION}_all.zip"
SHA_FILE="$SCRIPT_DIR/aipet-agent-windows-${VERSION}_all.zip.sha256"

if [[ ! -d "$WIN_DIR" ]]; then
    echo "ERROR: $WIN_DIR not found" >&2
    exit 1
fi

# 1. Sync agent code into the staging dir so the bundle is self-contained
cp "$SCRIPT_DIR/../aipet_agent.py" "$WIN_DIR/aipet_agent.py"
cp "$SCRIPT_DIR/../watchdog.py"    "$WIN_DIR/watchdog.py"

# 2. Required files (manifest -- order is the canonical zip order)
REQUIRED=(
    aipet-agent-service-install.bat
    aipet-agent-service-uninstall.bat
    aipet_agent.py
    install_windows.bat
    nssm-LICENSE.txt
    nssm.exe
    README-Windows.md
    uninstall_windows.bat
    watchdog.py
)
for f in "${REQUIRED[@]}"; do
    if [[ ! -f "$WIN_DIR/$f" ]]; then
        echo "ERROR: missing $WIN_DIR/$f" >&2
        exit 1
    fi
done

# 3. Build via Python's zipfile (zip CLI not always present on dev boxes;
#    Python is, since the rest of the project depends on it).
rm -f "$OUT_FILE"
python3 - "$OUT_FILE" "$WIN_DIR" "${REQUIRED[@]}" <<'PY'
import sys, zipfile, pathlib, time

out = pathlib.Path(sys.argv[1])
src = pathlib.Path(sys.argv[2])
names = sys.argv[3:]

# Fixed timestamp -- determinism across rebuilds
fixed_ts = (1980, 1, 1, 0, 0, 0)

with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name in names:
        path = src / name
        info = zipfile.ZipInfo(filename=name, date_time=fixed_ts)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o644 << 16) if not name.endswith(".bat") else (0o755 << 16)
        with open(path, "rb") as f:
            data = f.read()
        z.writestr(info, data)
        print(f"  {name:<40} {len(data):>9} bytes")

print(f"\n  -> {out} ({out.stat().st_size} bytes)")
PY

# 4. SHA256
sha256sum "$OUT_FILE" | awk '{print $1}' > "$SHA_FILE"

echo
echo "Built:  $OUT_FILE"
echo "Size:   $(stat -c%s "$OUT_FILE") bytes"
echo "SHA256: $(cat "$SHA_FILE")"
