import click
import datetime
import json
import gzip
import requests
import tarfile
import tempfile
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


from io import TextIOWrapper
from . import db
from .models import Vulnerability, Package, PackageVersion, VulnerabilityState, CPEMatch, VulnerabilityReference
from .version import APKVersion
from . import nvd


def rewrite_python(x): return 'py3-' + x.replace('_', '-').lower()
def rewrite_ruby(x): return 'ruby-' + x.replace('_', '-').lower()
def rewrite_perl(x): return 'perl-' + x.replace('_',
                                                '-').replace('::', '-').lower()


def rewrite_lua(x): return 'lua-' + x.replace('_', '-').lower()
def rewrite_vscode(x): return 'vscode-' + x.replace('_', '-').lower()


LANGUAGE_REWRITERS = {
    'python': rewrite_python,
    'ruby': rewrite_ruby,
    'perl': rewrite_perl,
    'lua': rewrite_lua,
    'visual_studio_code': rewrite_vscode,
}


def register(app):
    
    @app.cli.command('import-nvd', help='Import a NVD feed.')
    @click.argument('days')
    def import_nvd_cve(days: str):
        api = nvd.API()

        print(f'I: Importing NVD changes from {days} day(s) ago')

        cve_resp = api.cves(
            last_mod_start_date=datetime.datetime.now() - datetime.timedelta(days=int(days)),
            last_mod_end_date=datetime.datetime.now(),
        )

        if 'vulnerabilities' not in cve_resp:
            print(f"E: 'vulnerabilities' not found in NVD feed.")
            exit(1)

        for item in cve_resp['vulnerabilities']:
            process_nvd_cve_item(item)

        db.session.commit()
        print(f'I: Imported NVD feed successfully.')

    @app.cli.command('import-nvd-files', help='Import NVD CVEs from local JSON files.')
    @click.argument('directory')  
    def import_nvd_files(directory: str):
        """Import NVD CVEs from local JSON files with optimized batch processing"""
        import os
        import json
        import glob
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        if not os.path.exists(directory):
            print(f'E: Directory {directory} does not exist.')
            return
        
        # Find all CVE JSON files in the directory
        cve_files = glob.glob(os.path.join(directory, 'CVE-*.json'))
        
        if not cve_files:
            print(f'I: No CVE files found in {directory}')
            return
        
        print(f'I: Processing {len(cve_files)} CVE files from {directory} with optimized batch processing')
        
        # OPTIMIZED: High performance settings now safe with progressive cleanup
        max_workers = 20  # Full parallelization - progressive cleanup prevents resource buildup
        batch_size = 2000 # Large batches for efficiency - only processing one year at a time
        
        def parse_cve_file(cve_file):
            """Parse a single CVE file and return structured data"""
            try:
                with open(cve_file, 'r') as f:
                    cve_data = json.load(f)
                
                # cve_data is already in the correct format for vuln-list-nvd
                return parse_cve_data(cve_data), None
                
            except Exception as e:
                return None, str(e)
        
        # Process files in batches with parallel parsing
        processed_count = 0
        skipped_count = 0
        
        for batch_start in range(0, len(cve_files), batch_size):
            batch_end = min(batch_start + batch_size, len(cve_files))
            batch_files = cve_files[batch_start:batch_end]
            
            print(f'I: Processing batch {batch_start//batch_size + 1}/{(len(cve_files)-1)//batch_size + 1}: {len(batch_files)} files')
            
            # Parse all files in parallel (no database operations)
            batch_data = {
                'vulnerabilities': [],
                'references': [],
                'cpe_matches': []
            }
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all files in batch for parallel parsing
                futures = {executor.submit(parse_cve_file, cve_file): cve_file for cve_file in batch_files}
                
                batch_processed = 0
                batch_skipped = 0
                
                for future in as_completed(futures):
                    cve_data, error = future.result()
                    if cve_data:
                        batch_processed += 1
                        # Collect data for bulk operations
                        batch_data['vulnerabilities'].extend(cve_data['vulnerabilities'])
                        batch_data['references'].extend(cve_data['references'])
                        batch_data['cpe_matches'].extend(cve_data['cpe_matches'])
                    else:
                        batch_skipped += 1
                        if batch_skipped <= 5:  # Only show first few errors
                            print(f'W: Error: {error}')
            
            # Single bulk database operation for entire batch
            if batch_data['vulnerabilities']:
                with app.app_context():
                    bulk_insert_batch(batch_data)
                    db.session.commit()
                    print(f'   Bulk inserted: {len(batch_data["vulnerabilities"])} vulnerabilities, {len(batch_data["references"])} references, {len(batch_data["cpe_matches"])} CPE matches')
                    
                # Clear batch data and force garbage collection
                batch_data.clear()
                import gc
                gc.collect()
            
            processed_count += batch_processed
            skipped_count += batch_skipped
            
            print(f'   Batch complete: {batch_processed} processed, {batch_skipped} skipped')
            print(f'I: Progress: {processed_count}/{len(cve_files)} files processed ({(processed_count/len(cve_files)*100):.1f}%)')
        
        print(f'I: Processed {processed_count} CVEs from local files with optimized batch processing')
        if skipped_count > 0:
            print(f'W: Skipped {skipped_count} files due to errors')

    def parse_cve_data(cve_data):
        """Parse CVE data and return structured data for bulk insertion"""
        import re
        
        # vuln-list-nvd files have CVE data at root level, not wrapped in 'cve' key
        cve = cve_data  # Direct structure: {"id": "CVE-...", "descriptions": [...], ...}
        cve_id = cve.get('id', '')
        
        # Validate CVE ID format
        cve_pattern = r'^CVE-\d{4}-\d{4,7}$'
        if not re.match(cve_pattern, cve_id):
            return {'vulnerabilities': [], 'references': [], 'cpe_matches': []}
        
        # Extract description
        descriptions = cve.get('descriptions', [])
        cve_description = None
        for desc in descriptions:
            if desc.get('lang') == "en":
                cve_description = desc.get('value')
                break
        if not cve_description and descriptions:
            cve_description = descriptions[0].get('value')
        
        # Extract CVSS data - handle both v31 and v40 metrics
        metrics = cve.get('metrics', {})
        cvss3_score = None
        cvss3_vector = None
        
        # Try CVSS v3.1 first
        cvssMetricV31 = metrics.get('cvssMetricV31', [])
        if cvssMetricV31 and len(cvssMetricV31) > 0:
            impact = cvssMetricV31[0].get('cvssData', {})
            cvss3_score = impact.get('baseScore')
            cvss3_vector = impact.get('vectorString')
        
        # Fallback to CVSS v4.0 if v3.1 not available
        if not cvss3_score:
            cvssMetricV40 = metrics.get('cvssMetricV40', [])
            if cvssMetricV40 and len(cvssMetricV40) > 0:
                impact = cvssMetricV40[0].get('cvssData', {})
                cvss3_score = impact.get('baseScore')
                cvss3_vector = impact.get('vectorString')
        
        # Build vulnerability data
        vulnerability_data = {
            'cve_id': cve_id,
            'description': cve_description,
            'cvss3_score': cvss3_score,
            'cvss3_vector': cvss3_vector
        }
        
        # Parse references
        references_data = []
        if 'references' in cve:
            for ref in cve['references']:
                ref_type = ref.get('source', '')
                ref_tags = ref.get('tags', [])
                ref_uri = ref.get('url', '')
                
                if ref_uri:
                    if ref_tags:
                        ref_type = ref_tags[0]
                    
                    references_data.append({
                        'cve_id': cve_id,
                        'ref_type': ref_type,
                        'ref_uri': ref_uri
                    })
        
        # Parse CPE matches
        cpe_matches_data = []
        if 'configurations' in cve and len(cve['configurations']) > 0:
            for configuration in cve['configurations']:
                if 'nodes' in configuration:
                    for node in configuration['nodes']:
                        if 'cpeMatch' in node:
                            for match in node['cpeMatch']:
                                cpe_matches_data.append({
                                    'cve_id': cve_id,
                                    'cpe23Uri': match.get('criteria', ''),
                                    'vulnerable': match.get('vulnerable', False)
                                })
        
        return {
            'vulnerabilities': [vulnerability_data],
            'references': references_data,
            'cpe_matches': cpe_matches_data
        }

    def bulk_insert_batch(batch_data):
        """Perform bulk database operations for a batch of CVE data"""
        # FIXED: Removed ON CONFLICT clauses that were causing sqlite errors
        print(f"I: bulk_insert_batch called - using FIXED version (no ON CONFLICT)")
        from sqlalchemy.dialects.sqlite import insert
        
        # Bulk insert vulnerabilities with conflict handling
        if batch_data['vulnerabilities']:
            # Get existing CVE IDs to avoid duplicates
            existing_cves = set()
            cve_ids = [v['cve_id'] for v in batch_data['vulnerabilities']]
            if cve_ids:
                existing_vulns = db.session.query(Vulnerability.cve_id).filter(Vulnerability.cve_id.in_(cve_ids)).all()
                existing_cves = {row[0] for row in existing_vulns}
            
            # Filter out existing CVEs for insert
            new_vulns = [v for v in batch_data['vulnerabilities'] if v['cve_id'] not in existing_cves]
            
            if new_vulns:
                # Simple bulk insert for new vulnerabilities
                db.session.bulk_insert_mappings(Vulnerability, new_vulns)
                print(f'   Inserted {len(new_vulns)} new vulnerabilities')
            
            # Update existing vulnerabilities if needed
            existing_vulns = [v for v in batch_data['vulnerabilities'] if v['cve_id'] in existing_cves]
            if existing_vulns:
                for vuln_data in existing_vulns:
                    existing_vuln = db.session.query(Vulnerability).filter_by(cve_id=vuln_data['cve_id']).first()
                    if existing_vuln:
                        existing_vuln.description = vuln_data['description']
                        existing_vuln.cvss3_score = vuln_data['cvss3_score']
                        existing_vuln.cvss3_vector = vuln_data['cvss3_vector']
                print(f'   Updated {len(existing_vulns)} existing vulnerabilities')
        
        # Bulk insert references
        if batch_data['references']:
            # Get vulnerability IDs for references
            vuln_ids = {}
            for ref in batch_data['references']:
                cve_id = ref['cve_id']
                if cve_id not in vuln_ids:
                    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()
                    if vuln:
                        vuln_ids[cve_id] = vuln.vuln_id
            
            # Prepare reference data with vuln_id
            ref_data = []
            for ref in batch_data['references']:
                cve_id = ref['cve_id']
                if cve_id in vuln_ids:
                    ref_data.append({
                        'vuln_id': vuln_ids[cve_id],
                        'ref_type': ref['ref_type'],
                        'ref_uri': ref['ref_uri']
                    })
            
            if ref_data:
                # Simple bulk insert for references (duplicates filtered by unique constraints if any)
                db.session.bulk_insert_mappings(VulnerabilityReference, ref_data)
                print(f'   Inserted {len(ref_data)} references')
        
        # Bulk insert CPE matches with proper package creation
        if batch_data['cpe_matches']:
            # Get vulnerability IDs for CPE matches
            vuln_ids = {}
            for cpe in batch_data['cpe_matches']:
                cve_id = cpe['cve_id']
                if cve_id not in vuln_ids:
                    vuln = Vulnerability.query.filter_by(cve_id=cve_id).first()
                    if vuln:
                        vuln_ids[cve_id] = vuln.vuln_id
            
            # Create packages and CPE matches
            package_cache = {}
            cpe_matches_to_insert = []
            
            for cpe in batch_data['cpe_matches']:
                cve_id = cpe['cve_id']
                if cve_id in vuln_ids:
                    # Parse CPE URI to extract package name
                    package_name = extract_package_name_from_cpe(cpe['cpe23Uri'])
                    if package_name:
                        # Get or create package
                        if package_name not in package_cache:
                            pkg = Package.query.filter_by(package_name=package_name).first()
                            if not pkg:
                                pkg = Package(package_name=package_name)
                                db.session.add(pkg)
                                db.session.flush()  # Get the package_id
                            package_cache[package_name] = pkg.package_id
                        
                        # Prepare CPE match data
                        cpe_matches_to_insert.append({
                            'vuln_id': vuln_ids[cve_id],
                            'package_id': package_cache[package_name],
                            'vulnerable': cpe['vulnerable'],
                            'cpe_uri': cpe['cpe23Uri'],
                            'minimum_version': None,  # Parse from CPE if needed
                            'minimum_version_op': None,
                            'maximum_version': None,
                            'maximum_version_op': None
                        })
            
            if cpe_matches_to_insert:
                db.session.bulk_insert_mappings(CPEMatch, cpe_matches_to_insert)
                print(f'   Inserted {len(cpe_matches_to_insert)} CPE matches')
            else:
                print(f'   Skipped {len(batch_data["cpe_matches"])} CPE matches (could not parse package names)')

    def extract_package_name_from_cpe(cpe_uri):
        """Extract package name from CPE URI with Alpine Linux package name mapping"""
        try:
            # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            parts = cpe_uri.split(':')
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                
                # Alpine Linux package name mappings
                # Many packages in Alpine use just the product name, not vendor-product
                alpine_package_mappings = {
                    # Common cases where Alpine uses product name directly
                    ('debian', 'dpkg'): 'dpkg',
                    ('gnu', 'bash'): 'bash', 
                    ('apache', 'httpd'): 'apache2',
                    ('nginx', 'nginx'): 'nginx',
                    ('sqlite', 'sqlite'): 'sqlite',
                    ('python', 'python'): 'python3',
                    ('nodejs', 'node.js'): 'nodejs',
                    ('postgresql', 'postgresql'): 'postgresql',
                    ('mysql', 'mysql'): 'mysql',
                    ('redis', 'redis'): 'redis',
                    ('vim', 'vim'): 'vim',
                    ('git', 'git'): 'git',
                    ('openssh', 'openssh'): 'openssh',
                    ('openssl', 'openssl'): 'openssl',
                    ('curl', 'curl'): 'curl',
                    ('wget', 'wget'): 'wget',
                }
                
                # Check for specific Alpine mappings first
                if vendor != '*' and product != '*':
                    mapping_key = (vendor.lower(), product.lower())
                    if mapping_key in alpine_package_mappings:
                        return alpine_package_mappings[mapping_key]
                    
                    # For unknown combinations, prefer product name over vendor-product
                    # This matches Alpine's common pattern
                    return product
                elif product != '*':
                    return product
                elif vendor != '*':
                    return vendor
            return None
        except Exception:
            return None

    def process_nvd_cve_reference(vuln: Vulnerability, item: dict):
        ref_type = item['source']
        ref_tags = item.get('tags', [])

        ref_uri = item.get('url', None)
        if not ref_uri:
            return

        if ref_tags:
            ref_type = ref_tags[0]

        ref = VulnerabilityReference.find_or_create(vuln, ref_type, ref_uri)
        db.session.add(ref)

    def process_nvd_cve_references(vuln: Vulnerability, refs: list):
        [process_nvd_cve_reference(vuln, item) for item in refs]

    def process_nvd_cve_item(item: dict):
        if 'cve' not in item:
            return

        cve = item['cve']
        cve_id = cve.get('id', None)

        if not cve_id:
            return

        cve_description = select(
            cve.get('descriptions', []),
            lambda desc: desc['lang'] == "en"
        ).get('value', [])
        if not cve_description:
            return

        print(f'I: Processing {cve_id}.')

        impact = item.get('metrics', {}).get(
            'cvssMetricV31', {}).get('cvssData', {})

        cvss3_score = impact.get('baseScore', None)
        cvss3_vector = impact.get('vectorString', None)

        vuln = Vulnerability.find_or_create(cve_id)
        vuln.description = cve_description
        vuln.cvss3_score = cvss3_score
        vuln.cvss3_vector = cvss3_vector

        db.session.add(vuln)

        if 'configurations' in cve and len(cve['configurations']) > 0:
            process_nvd_cve_configurations(vuln, cve['configurations'][0])

        if 'references' in cve:
            process_nvd_cve_references(vuln, cve['references'])

    def match_uses_version_ranges(match: dict) -> bool:
        version_match_keywords = {
            'versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'}
        return version_match_keywords & set(match.keys()) != set()

    def process_nvd_cve_configurations(vuln: Vulnerability, configuration: dict):
        global LANGUAGE_REWRITERS

        def handle_match(match: dict):
            if 'criteria' not in match:
                return

            # if vulnerable is not specified, assume True.  maintainer can override
            # by adding a secfixes-override entry in their APKBUILD.
            cpe_uri = match.get('criteria')
            vulnerable = match.get('vulnerable', True)

            cpe_parts = cpe_uri.split(':')[3:6]
            cpe_language = cpe_uri.split(':')[10].lower()

            language_rewriter = LANGUAGE_REWRITERS.get(cpe_language, None)

            source_pkgname = cpe_parts[1]
            if language_rewriter:
                source_pkgname = language_rewriter(source_pkgname)

            cpe_vendor = cpe_parts[0]

            custom_rewriters = app.config.get('CUSTOM_REWRITERS', {})
            custom_rewriter_key = f'{cpe_vendor}:{source_pkgname}'
            custom_rewriter = custom_rewriters.get(custom_rewriter_key,
                                                   custom_rewriters.get(f'{cpe_vendor}:*', None))
            if custom_rewriter:
                source_pkgname = custom_rewriter(source_pkgname)

            source_version = cpe_parts[2] if cpe_parts[2] != '*' else None

            # some NVD CPE match nodes have versionStartIncluding/versionEndIncluding (same for Excluding),
            # so extract this data
            using_version_ranges = match_uses_version_ranges(match)

            max_version = match.get('versionEndIncluding', match.get(
                'versionEndExcluding', source_version))
            min_version = match.get('versionStartIncluding', match.get(
                'versionStartExcluding', None))

            min_version_op = '=='
            max_version_op = '=='

            # specify the correct op based on whether versionStartIncluding or versionStartExcluding are used
            if using_version_ranges:
                min_version_op = '>='
                if 'versionStartExcluding' in match:
                    min_version_op = '>'

                # same, but for versionEndIncluding/Excluding
                max_version_op = '<='
                if 'versionEndExcluding' in match:
                    max_version_op = '<'

            process_nvd_cve_configuration_item(
                vuln, source_pkgname, min_version, min_version_op, max_version, max_version_op, vulnerable, cpe_uri)

        def walk_nodes(nodes: list):
            for node in nodes or []:
                for m in node.get('cpeMatch', []) or []:
                    handle_match(m)
                # Children may contain nested nodes
                for child in node.get('children', []) or []:
                    # child is itself a node with potential cpeMatch/children
                    walk_nodes([child])

        if 'nodes' not in configuration or not configuration['nodes']:
            return

        walk_nodes(configuration['nodes'])

    def process_nvd_cve_configuration_item(vuln: Vulnerability, source_pkgname: str,
                                           min_version: str, min_version_op: str,
                                           max_version: str, max_version_op: str, vulnerable: bool, cpe_uri: str):
        pkg = Package.find_or_create(source_pkgname)
        db.session.add(pkg)

        cm = CPEMatch.find_or_create(
            pkg, vuln, min_version, min_version_op, max_version, max_version_op, vulnerable, cpe_uri)
        db.session.add(cm)

    @app.cli.command('import-secfixes', help='Import secfixes feeds.')
    @click.argument('repo', required=False)
    def import_secfixes(repo: str):
        repositories = app.config.get('SECFIXES_REPOSITORIES', {})

        if not repositories:
            print("E: No SECFIXES_REPOSITORIES configured.")
            exit(1)

        if repo:
            uri = repositories.get(repo)
            if uri:
                import_secfixes_feed(repo, uri)
                return

            print(f"E: Repository {repo} not found in SECFIXES_REPOSITORIES.")
            exit(1)

        for repo, uri in repositories.items():
            import_secfixes_feed(repo, uri)

    def import_secfixes_feed(repo: str, uri: str):
        print(f'I: [{repo}] Downloading {uri}')

        r = requests.get(uri)
        data = r.json()

        packages = data.get('packages', [])

        for package in packages:
            import_secfixes_package(repo, package['pkg'])
        db.session.commit()

    def import_secfixes_package(repo: str, package: dict):
        pkg = Package.find_or_create(package['name'])
        db.session.add(pkg)

        secfixes = package.get('secfixes', {})
        for ver, fixes in secfixes.items():
            pkgver = PackageVersion.find_or_create(pkg, ver, repo)
            db.session.add(pkgver)

            for fix in fixes:
                fix = fix.split()[0]
                vuln = Vulnerability.find_or_create(fix)
                db.session.add(vuln)

                state = VulnerabilityState.find_or_create(pkgver, vuln)
                state.fixed = True

                db.session.add(state)

    @app.cli.command('import-rejections', help='Import security rejections feeds.')
    @click.argument('repo', required=False)
    def import_security_rejections(repo: str):
        repositories = app.config.get('SECURITY_REJECTIONS', {})
        if repo:
            uri = repositories.get(repo)
            if uri:
                import_security_rejections_feed(repo, uri)
                return

            print(f"E: Repository {repo} not found in SECURITY_REJECTIONS.")
            exit(1)

        for repo, uri in app.config.get('SECURITY_REJECTIONS', {}).items():
            import_security_rejections_feed(repo, uri)

    def import_security_rejections_feed(repo: str, uri: str):
        print(f'I: [{repo}] Downloading {uri}')

        r = requests.get(uri)

        try:
            feed = yaml.load(r.content, Loader=yaml.SafeLoader)
            [import_security_rejections_package(
                repo, k, v) for k, v in feed.items()]
        except Exception as e:
            print(
                f'E: Encountered {e} while parsing security rejections feed.')
            exit(1)

        db.session.commit()

    def import_security_rejections_package(repo: str, pkgname: str, cves: list):
        pkg = Package.find_or_create(pkgname)
        db.session.add(pkg)

        pkgver = PackageVersion.find_or_create(pkg, '0', repo)
        db.session.add(pkgver)

        for cve in cves:
            vuln = Vulnerability.find_or_create(cve)
            db.session.add(vuln)

            state = VulnerabilityState.find_or_create(pkgver, vuln)
            state.fixed = True

            db.session.add(state)

    @app.cli.command('import-apkindex', help='Import APK repository indices.')
    @click.argument('repo', required=False)
    def import_apkindex(repo: str):
        repositories = app.config.get('APKINDEX_REPOSITORIES', {})

        if repo:
            uri = repositories.get(repo)
            if uri:
                import_apkindex_repo(repo, uri)
                return

            print(f"E: Repository {repo} not found in APKINDEX_REPOSITORIES.")
            exit(1)

        for repo, uri in repositories.items():
            import_apkindex_repo(repo, uri)

    def import_apkindex_repo(repo: str, uri: str):
        print(f'I: [{repo}] Downloading {uri}')

        r = requests.get(uri)

        with tempfile.TemporaryFile() as f:
            f.write(r.content)
            f.seek(0)

            import_apkindex_payload(repo, f)

    def import_apkindex_pkg(pkg: dict, repo: str):
        origin = pkg.get('o', pkg['P'])
        p = Package.find_or_create(origin)
        db.session.add(p)

        pkgver = PackageVersion.find_or_create(p, pkg['V'], repo)
        pkgver.published = True

        if origin == pkg['P']:
            pkgver.maintainer = pkg.get('m', None)

        db.session.add(pkgver)

    def import_apkindex_idx(index_data, repo: str):
        current_pkg = {}

        for line in index_data:
            data = line.strip().split(':', 1)

            if len(data) == 1:
                import_apkindex_pkg(current_pkg, repo)
                current_pkg = {}
            else:
                current_pkg[data[0]] = data[1]
        db.session.commit()

    def import_apkindex_payload(repo: str, file):
        print(f'I: [{repo}] Processing APKINDEX')

        with tarfile.open(mode='r', fileobj=file, debug=3) as tf:
            for tarentry in tf.getmembers():
                if tarentry.name == 'APKINDEX':
                    data = tf.extractfile(tarentry)
                    import_apkindex_idx(TextIOWrapper(data), repo)

    @app.cli.command('update-states', help='Update the package vulnerability states.')
    @click.argument('repo', required=False)
    def update_states(repo: str):
        repositories = app.config.get('SECFIXES_REPOSITORIES', {})
        if repo:
            if not repositories.get(repo):
                print(
                    f"E: Repository {repo} not found in SECFIXES_REPOSITORIES.")
                exit(1)

            update_states_for_repo_tag(repo)
            return

        for repo, _ in repositories.items():
            update_states_for_repo_tag(repo)

    def update_states_for_repo_tag(repo: str):
        print(f'I: [{repo}] Processing updates.')

        for pkgver in PackageVersion.query.filter_by(repo=repo, published=True):
            update_states_for_pkgver(pkgver)
        db.session.commit()

    def update_states_for_pkgver(pkgver: PackageVersion):
        pkg = pkgver.package

        print(f'I: Considering {pkgver} ({pkg})')

        # walk the CPE matches to find associated vulnerabilities
        for cpe_match in pkg.cpe_matches:
            update_states_if_pkgver_matches_cpe_match(pkgver, cpe_match)

    def update_states_if_pkgver_matches_cpe_match(pkgver: PackageVersion, cpe_match: CPEMatch):
        vuln = cpe_match.vuln
        pv = APKVersion(pkgver.version)

        print(f'I: Evaluating {cpe_match} for {vuln} against {pkgver}')

        if not cpe_match.matches_version(pkgver):
            print(f'I: CPE match does not match {pkgver}')
            return

        # Look for a fixed VulnerabilityState that is older than pkgver.
        fixed_states = VulnerabilityState.query.filter_by(
            vuln_id=vuln.vuln_id, fixed=True).all()
        fixed_states = [
            state for state in fixed_states if state.package_version.repo == pkgver.repo]
        fixed_states = sorted(
            fixed_states, key=lambda x: APKVersion(x.package_version.version))

        fixed_state = fixed_states[0] if fixed_states else None
        fixed = False
        if not fixed_state:
            print(
                f'I: No fix recorded against any {pkgver.package} version for {vuln}')
        else:
            print(
                f'I: Fix recorded in {fixed_state.package_version} for {vuln}')

            fv = APKVersion(fixed_state.package_version.version)
            fixed = pv >= fv

        vuln_state = VulnerabilityState.find_or_create(pkgver, vuln)
        if vuln_state.fixed:
            return

        vuln_state.fixed = fixed
        db.session.add(vuln_state)


def select(lst, predicate):
    for elem in lst:
        if predicate(elem):
            return elem
    return {}
