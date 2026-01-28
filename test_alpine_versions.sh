#!/bin/bash
# Test script for Alpine versions discovery and config update
# This script tests the update_alpine_config.py script locally

set -e

CONFIG_FILE="secfixes_tracker/application.cfg"
BACKUP_FILE="${CONFIG_FILE}.backup"

# Create a backup of the config file
if [ -f "$CONFIG_FILE" ]; then
  echo "=== Creating backup of application.cfg ==="
  cp "$CONFIG_FILE" "$BACKUP_FILE"
  echo "Backup created: $BACKUP_FILE"
  echo ""
fi

# Run the update script
echo "=== Running update_alpine_config.py ==="
python3 scripts/update_alpine_config.py

echo ""
echo "=== Verifying Python syntax ==="
python3 -c "
import ast

config_file = '$CONFIG_FILE'

# Check syntax
try:
    with open(config_file, 'r') as f:
        code = f.read()
    ast.parse(code)
    print('✓ Python syntax is valid')
except SyntaxError as e:
    print(f'✗ Syntax error: {e}')
    exit(1)

# Load and verify config
try:
    config = {}
    exec(compile(code, config_file, 'exec'), config)
    
    if 'alpine_versions' in config:
        print(f'✓ alpine_versions = {config[\"alpine_versions\"]}')
        print(f'✓ SECFIXES_REPOSITORIES has {len(config[\"SECFIXES_REPOSITORIES\"])} entries')
        print(f'✓ APKINDEX_REPOSITORIES has {len(config[\"APKINDEX_REPOSITORIES\"])} entries')
    else:
        print('✗ alpine_versions not found in config')
        exit(1)
except Exception as e:
    print(f'✗ Error loading config: {e}')
    exit(1)
"

echo ""
echo "=== Test completed successfully! ==="
echo ""
echo "To restore the original config file, run:"
echo "  cp $BACKUP_FILE $CONFIG_FILE"
