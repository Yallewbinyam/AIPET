#!/usr/bin/env bash
# Builds aipet-agent_<version>_all.deb from agent/packaging/deb/
set -e

VERSION="${VERSION:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/deb"
OUTPUT_FILE="$SCRIPT_DIR/aipet-agent_${VERSION}_all.deb"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "ERROR: dpkg-deb not installed. Install with: sudo apt-get install dpkg" >&2
    exit 1
fi

# Pin version in control file (idempotent)
sed -i "s/^Version: .*/Version: $VERSION/" "$SOURCE_DIR/DEBIAN/control"

# Sync the latest agent source into the package tree
cp "$SCRIPT_DIR/../aipet_agent.py" "$SOURCE_DIR/opt/aipet-agent/aipet_agent.py"
cp "$SCRIPT_DIR/../watchdog.py"    "$SOURCE_DIR/opt/aipet-agent/watchdog.py"

# Permissions: maintainer scripts and bin wrapper must be 0755
chmod 0755 "$SOURCE_DIR/DEBIAN/postinst" "$SOURCE_DIR/DEBIAN/prerm" "$SOURCE_DIR/DEBIAN/postrm"
chmod 0755 "$SOURCE_DIR/usr/bin/aipet-agent"
chmod 0644 "$SOURCE_DIR/lib/systemd/system/aipet-agent.service"
chmod 0644 "$SOURCE_DIR/etc/aipet-agent/agent.conf.example"
chmod 0644 "$SOURCE_DIR/opt/aipet-agent/aipet_agent.py" "$SOURCE_DIR/opt/aipet-agent/watchdog.py"
chmod 0644 "$SOURCE_DIR/opt/aipet-agent/requirements.txt"
chmod 0644 "$SOURCE_DIR/usr/share/doc/aipet-agent/README.md"

# Build
dpkg-deb --build --root-owner-group "$SOURCE_DIR" "$OUTPUT_FILE"

echo ""
echo "✓ Built: $OUTPUT_FILE"
ls -lh "$OUTPUT_FILE" | awk '{print "  Size: " $5}'
echo ""
echo "Test install:"
echo "  sudo apt-get install $OUTPUT_FILE"
echo ""
echo "Test uninstall:"
echo "  sudo apt-get remove --purge aipet-agent"
