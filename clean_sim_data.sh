#!/bin/bash
# Clean simulator wallet data for fresh start
cd "$(dirname "$0")/ui_simulator/assets" || exit 1
for f in user*_data.json user*_secret.json user*_rsa.json user*_multisig.json coin*.json device_setting.json; do
    [ -f "$f" ] && truncate -s 0 "$f"
done
echo "Simulator data cleared."
