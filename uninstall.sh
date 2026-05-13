#!/bin/bash
# Tor Manager Plugin - Uninstall
echo "Removing Tor Manager plugin..."
rm -f /www/server/panel/BTPanel/static/img/soft_ico/ico-tor_manager.png 2>/dev/null
rm -f /www/server/panel/BTPanel/static/vite/images/soft-ico/ico-tor_manager.png 2>/dev/null
rm -f /www/server/panel/static/img/soft_ico/ico-tor_manager.png 2>/dev/null
rm -rf /www/server/panel/plugin/tor_manager
echo "Tor Manager removed. Restart aaPanel: bt restart"
