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
        
        # Check if API key is available
        has_api_key = api.api_token is not None
        if has_api_key:
            print(f'I: Using NVD API with key for higher rate limits')
        else:
            print(f'W: No NVD API key found, using limited rate (5 req/min)')
        
        # Check if input is a year (4 digits) for year-based import
        # But exclude large numbers that are clearly days (like 2920)
        if days.isdigit() and len(days) == 4 and int(days) <= 2025:
            year = int(days)
            current_year = datetime.datetime.now().year
            
            if year < 1999 or year > current_year:
                print(f'E: Invalid year {year}. Must be between 1999 and {current_year}')
                return
                
            print(f'I: Importing NVD CVEs for year {year}')
            
            try:
                # NVD API 2.0 has a 120-day limit for date ranges
                # We need to break the year into 120-day chunks
                print(f'I: NVD API 2.0 has 120-day limit for date ranges, using chunked approach')
                
                # Break the year into 120-day chunks
                start_date = datetime.datetime(year, 1, 1)
                end_date = datetime.datetime(year, 12, 31, 23, 59, 59)
                
                # Calculate chunks of 30 days (smaller chunks = better parallelism)
                chunks = []
                current_start = start_date
                chunk_days = 29  # Smaller chunks for optimal parallel distribution
                
                while current_start < end_date:
                    current_end = min(current_start + datetime.timedelta(days=chunk_days, hours=23, minutes=59, seconds=59), end_date)
                    chunks.append((current_start, current_end))
                    current_start = current_end + datetime.timedelta(seconds=1)
                
                print(f'I: Will process {len(chunks)} chunks for year {year}')
                
                print(f'I: Breaking {year} into {len(chunks)} chunks of max 30 days each for optimal parallelism')
                
                # Estimate time with parallel processing
                max_workers = 12 if has_api_key else 4  # Higher workers for pagination workload
                estimated_time = len(chunks) * 2.0 / max_workers  # Optimized for smaller chunks
                print(f'I: Estimated time with {max_workers} parallel workers: {estimated_time/60:.1f} minutes for {year}')
                
                total_found = 0
                db_lock = Lock()  # Thread-safe database access
                
                def process_chunk(chunk_info):
                    """Process a single chunk in parallel"""
                    i, chunk_start, chunk_end = chunk_info
                    
                    try:
                        # Use publication date filtering with 120-day limit
                        # Handle pagination to get ALL CVEs in date range
                        all_vulnerabilities = []
                        start_index = 0
                        results_per_page = 2000
                        
                        while True:
                            cve_resp = api.cves(
                                pub_start_date=chunk_start,
                                pub_end_date=chunk_end,
                                start_index=start_index
                            )
                            
                            if 'vulnerabilities' not in cve_resp:
                                print(f'E: No vulnerabilities found in chunk {i}')
                                break
                                
                            vulnerabilities = cve_resp['vulnerabilities']
                            total_results = cve_resp.get('totalResults', 0)
                            current_count = len(vulnerabilities)
                            
                            all_vulnerabilities.extend(vulnerabilities)
                            
                            print(f'I: Found {current_count} CVEs in chunk {i}/{len(chunks)} page {start_index//results_per_page + 1} (total: {len(all_vulnerabilities)}/{total_results})')
                            
                            # Check if we've got all results
                            if len(all_vulnerabilities) >= total_results or current_count < results_per_page:
                                break
                                
                            start_index += results_per_page
                            
                            # Brief pause only for pagination within chunk (with API key)
                            if has_api_key:
                                import time
                                time.sleep(0.2)  # Minimal delay with API key
                        
                        vulnerabilities = all_vulnerabilities
                        print(f'I: Chunk {i} complete: {len(vulnerabilities)} total CVEs processed')
                        
                        # Process each vulnerability with filtering
                        import re
                        processed_items = []
                        skipped_count = 0
                        
                        for item in vulnerabilities:
                            if 'cve' in item:
                                cve_id = item['cve'].get('id', '')
                                if cve_id.startswith('CVE-') and re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id):
                                    processed_items.append(item)
                                else:
                                    skipped_count += 1
                            else:
                                skipped_count += 1
                        
                        # Thread-safe database write with application context
                        with db_lock:
                            # Create application context for this thread
                            with app.app_context():
                                for item in processed_items:
                                    process_nvd_cve_item(item)
                                db.session.commit()
                        
                        processed_count = len(processed_items)
                        
                        if skipped_count > 0:
                            print(f'I: Chunk {i}: Processed {processed_count} CVEs, skipped {skipped_count} non-CVE entries')
                        
                        # Show progress
                        progress = (i / len(chunks)) * 100
                        print(f'I: Progress: {progress:.1f}% ({i}/{len(chunks)} chunks)')
                        
                        return processed_count, skipped_count
                        
                    except Exception as e:
                        print(f'E: Error processing chunk {i}: {e}')
                        with db_lock:
                            with app.app_context():
                                db.session.rollback()
                        return 0, 0
                
                # Parallel processing with ThreadPoolExecutor
                print(f'I: Using {max_workers} parallel workers for API calls')
                
                chunk_infos = [(i, chunk_start, chunk_end) for i, (chunk_start, chunk_end) in enumerate(chunks, 1)]
                
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    # Submit all chunks for parallel processing
                    futures = {executor.submit(process_chunk, chunk_info): chunk_info for chunk_info in chunk_infos}
                    
                    # Process results as they complete
                    for future in as_completed(futures):
                        processed_count, skipped_count = future.result()
                        total_found += processed_count
                
                print(f'I: Successfully imported {total_found} CVEs for {year}')
                
            except Exception as e:
                print(f'E: Error importing CVEs for {year}: {e}')
                db.session.rollback()
            return
        
        # Original logic for days-based import
        total_days = int(days)
        print(f'I: Importing NVD changes from {days} day(s) ago')
        
        # For large date ranges, use pagination instead of date filtering
        # (NVD API 2.0 date filtering doesn't work - returns 404 errors)
        if total_days > 365:  # More than 1 year
            print(f'I: Large date range detected ({total_days} days)')
            print(f'I: Using pagination approach (NVD API date filtering not available)')
            
            # Calculate how many pages we need to get recent CVEs
            # NVD API has ~315k total CVEs, sorted oldest first
            # To get recent CVEs, we need to start from higher indices
            total_cves = 314940  # Approximate total from API
            results_per_page = 2000
            
            # For 8 years, we want CVEs from roughly the last 8 years
            # Estimate: 8 years = ~2920 days, assume ~100 CVEs per day = ~292k CVEs
            # So we want to start from index ~22k to get recent CVEs
            start_index = max(0, total_cves - (total_days * 100))  # Rough estimate
            end_index = total_cves
            
            print(f'I: Will fetch CVEs from index {start_index} to {end_index}')
            print(f'I: This should include recent CVEs from the last {total_days} days')
            
            current_index = start_index
            page_count = 0
            
            while current_index < end_index:
                page_count += 1
                progress = ((current_index - start_index) / (end_index - start_index)) * 100
                print(f'I: Processing page {page_count}: index {current_index} ({progress:.1f}%)')
                
                # Retry logic with exponential backoff for rate limiting
                max_retries = 5
                retry_count = 0
                success = False
                
                while retry_count < max_retries and not success:
                    try:
                        cve_resp = api.cves(start_index=current_index)
                        
                        if 'vulnerabilities' in cve_resp and cve_resp['vulnerabilities']:
                            print(f'I: Found {len(cve_resp["vulnerabilities"])} CVEs in this page')
                            for item in cve_resp['vulnerabilities']:
                                process_nvd_cve_item(item)
                            
                            db.session.commit()
                            print(f'I: Committed page {page_count}')
                        else:
                            print(f'I: No CVEs found in page {page_count}')
                        
                        success = True
                        
                    except Exception as e:
                        retry_count += 1
                        error_msg = str(e)
                        
                        if "429" in error_msg or "Too Many Requests" in error_msg:
                            # Rate limit hit - exponential backoff
                            if has_api_key:
                                wait_time = min(2 ** retry_count, 30)  # Max 30 seconds with API key
                            else:
                                wait_time = min(2 ** retry_count, 60)  # Max 60 seconds without API key
                            print(f'W: Rate limit hit for page {page_count}, retry {retry_count}/{max_retries}, waiting {wait_time}s...')
                            import time
                            time.sleep(wait_time)
                        elif "404" in error_msg:
                            # 404 error - likely no more data, stop
                            print(f'W: No more data found at index {current_index} (404), stopping...')
                            success = True  # Treat as success to stop
                        else:
                            # Other error - wait and retry
                            wait_time = min(2 ** retry_count, 30)  # Max 30 seconds
                            print(f'W: Error processing page {page_count}, retry {retry_count}/{max_retries}: {error_msg}')
                            print(f'I: Waiting {wait_time}s before retry...')
                            import time
                            time.sleep(wait_time)
                
                if not success:
                    print(f'E: Failed to process page {page_count} after {max_retries} retries, stopping...')
                    break
                
                # Move to next page
                current_index += results_per_page
                
                # Brief pause between pages to be respectful to the API
                if has_api_key:
                    wait_time = 1  # 1 second with API key
                else:
                    wait_time = 3  # 3 seconds without API key
                print(f'I: Waiting {wait_time} second(s) before next page...')
                import time
                time.sleep(wait_time)
                
        else:
            # For smaller date ranges, use original approach
            cve_resp = api.cves(
                last_mod_start_date=datetime.datetime.now() - datetime.timedelta(days=total_days),
                last_mod_end_date=datetime.datetime.now(),
            )

            if 'vulnerabilities' not in cve_resp:
                print(f"E: 'vulnerabilities' not found in NVD feed.")
                exit(1)

            for item in cve_resp['vulnerabilities']:
                process_nvd_cve_item(item)

            db.session.commit()
        
        print(f'I: Imported NVD feed successfully.')

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
        
        # Filter to only process standard CVE-* format entries
        # Skip non-CVE entries like xpe.json files
        if not cve_id.startswith('CVE-'):
            print(f'I: Skipping non-CVE entry: {cve_id}')
            return
        
        # Additional validation: ensure it follows CVE-YYYY-NNNNN format
        import re
        cve_pattern = r'^CVE-\d{4}-\d{4,7}$'
        if not re.match(cve_pattern, cve_id):
            print(f'I: Skipping invalid CVE format: {cve_id}')
            return

        descriptions = cve.get('descriptions', [])
        cve_description = select(
            descriptions,
            lambda desc: desc.get('lang') == "en"
        ).get('value', None)
        # Fallback to first description value if EN not present
        if not cve_description and descriptions:
            cve_description = descriptions[0].get('value')

        print(f'I: Processing {cve_id}.')

        # NVD API 2.0: cvssMetricV31 is a list, not a dict
        cvssMetricV31 = cve.get('metrics', {}).get('cvssMetricV31', [])
        if cvssMetricV31 and len(cvssMetricV31) > 0:
            impact = cvssMetricV31[0].get('cvssData', {})
        else:
            impact = {}

        cvss3_score = impact.get('baseScore', None)
        cvss3_vector = impact.get('vectorString', None)

        vuln = Vulnerability.find_or_create(cve_id)
        vuln.description = cve_description
        vuln.cvss3_score = cvss3_score
        vuln.cvss3_vector = cvss3_vector

        db.session.add(vuln)

        if 'configurations' in cve and len(cve['configurations']) > 0:
            # Process all configuration blocks, not just the first
            for configuration in cve['configurations']:
                process_nvd_cve_configurations(vuln, configuration)

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
