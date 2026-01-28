#!/usr/bin/env python3
"""
Update application.cfg with Alpine Linux versions from secdb.alpinelinux.org

This script:
1. Fetches available Alpine versions from https://secdb.alpinelinux.org/
2. Filters versions >= 3.10
3. Updates alpine_versions, SECFIXES_REPOSITORIES, and APKINDEX_REPOSITORIES
   in the application.cfg file
"""

import re
import sys
import urllib.request
from pathlib import Path


def fetch_alpine_versions(min_version="3.10"):
    """Fetch Alpine versions from secdb.alpinelinux.org"""
    url = "https://secdb.alpinelinux.org/"
    
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            html = response.read().decode('utf-8')
    except Exception as e:
        print(f"ERROR: Failed to fetch {url}: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Extract version directories from HTML (handles href="v3.XX/" format)
    pattern = r'href="v(\d+\.\d+)/"'
    versions = re.findall(pattern, html)
    
    if not versions:
        print("ERROR: No versions found", file=sys.stderr)
        sys.exit(1)
    
    # Filter versions >= min_version and sort
    min_major, min_minor = map(int, min_version.split('.'))
    filtered = []
    for v in versions:
        major, minor = map(int, v.split('.'))
        if major > min_major or (major == min_major and minor >= min_minor):
            filtered.append(v)
    
    # Sort by version number
    filtered.sort(key=lambda x: tuple(map(int, x.split('.'))))
    
    return filtered


def build_secfixes_repositories(versions):
    """Build SECFIXES_REPOSITORIES dictionary entries"""
    entries = []
    for version in versions:
        entries.append(f"    '{version}-main': 'https://secdb.alpinelinux.org/v{version}/main.json',")
        entries.append(f"    '{version}-community': 'https://secdb.alpinelinux.org/v{version}/community.json',")
    # Add edge entries
    entries.append("    'edge-main': 'https://secdb.alpinelinux.org/edge/main.json',")
    entries.append("    'edge-community': 'https://secdb.alpinelinux.org/edge/community.json',")
    return entries


def build_apkindex_repositories(versions):
    """Build APKINDEX_REPOSITORIES dictionary entries"""
    entries = []
    for version in versions:
        entries.append(f"    '{version}-main': 'https://dl-cdn.alpinelinux.org/alpine/v{version}/main/x86_64/APKINDEX.tar.gz',")
        entries.append(f"    '{version}-community': 'https://dl-cdn.alpinelinux.org/alpine/v{version}/community/x86_64/APKINDEX.tar.gz',")
    # Add edge entries
    entries.append("    'edge-main': 'https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/APKINDEX.tar.gz',")
    entries.append("    'edge-community': 'https://dl-cdn.alpinelinux.org/alpine/edge/community/x86_64/APKINDEX.tar.gz',")
    return entries


def update_config_file(config_path, versions):
    """Update the application.cfg file with new versions"""
    versions_str = ','.join(versions)
    
    # Read the config file
    with open(config_path, 'r') as f:
        content = f.read()
    
    # Update alpine_versions
    if re.search(r'^alpine_versions\s*=', content, re.MULTILINE):
        content = re.sub(
            r'^alpine_versions\s*=.*',
            f'alpine_versions = "{versions_str}"',
            content,
            flags=re.MULTILINE
        )
    else:
        # Add after SQLALCHEMY_TRACK_MODIFICATIONS if line doesn't exist
        content = re.sub(
            r'(SQLALCHEMY_TRACK_MODIFICATIONS = False)',
            rf'\1\nalpine_versions = "{versions_str}"',
            content
        )
    
    # Build new dictionary entries
    secfixes_entries = build_secfixes_repositories(versions)
    apkindex_entries = build_apkindex_repositories(versions)
    
    # Replace SECFIXES_REPOSITORIES
    secfixes_pattern = r'SECFIXES_REPOSITORIES\s*=\s*\{[^}]*\}'
    secfixes_replacement = 'SECFIXES_REPOSITORIES = {\n' + '\n'.join(secfixes_entries) + '\n}'
    content = re.sub(secfixes_pattern, secfixes_replacement, content, flags=re.DOTALL)
    
    # Replace APKINDEX_REPOSITORIES
    apkindex_pattern = r'APKINDEX_REPOSITORIES\s*=\s*\{[^}]*\}'
    apkindex_replacement = 'APKINDEX_REPOSITORIES = {\n' + '\n'.join(apkindex_entries) + '\n}'
    content = re.sub(apkindex_pattern, apkindex_replacement, content, flags=re.DOTALL)
    
    # Write back
    with open(config_path, 'w') as f:
        f.write(content)
    
    return versions_str


def main():
    # Default config path (can be overridden by argument)
    config_path = Path("secfixes_tracker/application.cfg")
    if len(sys.argv) > 1:
        config_path = Path(sys.argv[1])
    
    if not config_path.exists():
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    
    print("=== Discovering Alpine versions from secdb ===")
    versions = fetch_alpine_versions(min_version="3.10")
    print(f"Discovered {len(versions)} versions: {', '.join(versions)}")
    
    print("\n=== Updating application.cfg ===")
    versions_str = update_config_file(config_path, versions)
    
    print(f"✓ Updated alpine_versions with {len(versions)} versions")
    print(f"✓ Updated SECFIXES_REPOSITORIES with {len(versions)} versions + edge")
    print(f"✓ Updated APKINDEX_REPOSITORIES with {len(versions)} versions + edge")
    
    # Output for verification
    print(f"\nalpine_versions = \"{versions_str}\"")


if __name__ == "__main__":
    main()
