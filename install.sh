#!/bin/bash
# Tor Manager Plugin v3.4 - Install Script

PLUGIN_DIR="/www/server/panel/plugin/tor_manager"
ICON_SOURCE="${PLUGIN_DIR}/icon.png"

echo "Installing Tor Manager v3.4..."

# Clear Python cache
find "${PLUGIN_DIR}" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
find "${PLUGIN_DIR}" -name "*.pyc" -delete 2>/dev/null

# Copy icon to ALL known aaPanel icon locations
if [ -f "${ICON_SOURCE}" ]; then
    echo "Installing plugin icon..."

    # Location 1: BTPanel/static/img/soft_ico/ (classic path)
    ICO_DIR1="/www/server/panel/BTPanel/static/img/soft_ico"
    if [ -d "$(dirname "$ICO_DIR1")" ]; then
        mkdir -p "$ICO_DIR1"
        cp -f "${ICON_SOURCE}" "${ICO_DIR1}/ico-tor_manager.png"
        echo "  -> ${ICO_DIR1}/ico-tor_manager.png"
    fi

    # Location 2: BTPanel/static/vite/images/soft-ico/ (vite/new panel)
    ICO_DIR2="/www/server/panel/BTPanel/static/vite/images/soft-ico"
    if [ -d "$(dirname "$ICO_DIR2")" ]; then
        mkdir -p "$ICO_DIR2"
        cp -f "${ICON_SOURCE}" "${ICO_DIR2}/ico-tor_manager.png"
        chmod 755 "${ICO_DIR2}/ico-tor_manager.png"
        echo "  -> ${ICO_DIR2}/ico-tor_manager.png (755)"
    fi

    # Location 3: static/img/soft_ico/ (alternate)
    ICO_DIR3="/www/server/panel/static/img/soft_ico"
    if [ -d "$(dirname "$ICO_DIR3")" ]; then
        mkdir -p "$ICO_DIR3"
        cp -f "${ICON_SOURCE}" "${ICO_DIR3}/ico-tor_manager.png"
        echo "  -> ${ICO_DIR3}/ico-tor_manager.png"
    fi

    echo "Icon installed to all locations."
else
    echo "WARNING: icon.png not found in plugin directory."
fi

# Set permissions
chmod -R 755 "${PLUGIN_DIR}"
chmod 644 "${PLUGIN_DIR}"/*.py "${PLUGIN_DIR}"/*.html "${PLUGIN_DIR}"/*.json "${PLUGIN_DIR}"/*.png 2>/dev/null

# Force browser cache clear for icon by touching with new timestamp
touch /www/server/panel/BTPanel/static/img/soft_ico/ico-tor_manager.png 2>/dev/null
touch /www/server/panel/BTPanel/static/vite/images/soft-ico/ico-tor_manager.png 2>/dev/null

echo ""
echo "Tor Manager v3.4 installed. Restart aaPanel: bt restart"
echo "NOTE: Clear browser cache (Ctrl+Shift+R) to see new icon."
