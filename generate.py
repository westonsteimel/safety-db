import datetime
import glob
import gzip
import json
import os
import requests
import shutil
import subprocess
import time
import toml

ids = set()
insecure_full = {}
insecure = {}

shutil.rmtree('./.input/package-metadata', ignore_errors=True)
subprocess.run(['git', 'clone', '--depth', '1', 'https://github.com/westonsteimel/package-metadata.git', './.input/package-metadata'])

package_metadata_revision = subprocess.run(\
    ['git', '-C', './.input/package-metadata/', 'rev-parse', 'HEAD'], \
    capture_output=True \
).stdout.decode('utf-8').strip()
print(package_metadata_revision)

package_metadata_files = glob.glob(f'./.input/package-metadata/pypi/**/*.toml', recursive=True)
cpe_to_packages_lookup = {}

for metadata_file in package_metadata_files:
    with open(metadata_file, 'r+') as f:
        metadata = toml.load(f)
        name = metadata['name'].lower()

        for cpe_config in metadata.get('cpe_configurations', []):
            vendor = cpe_config.get('vendor')
            product = cpe_config.get('product')
            target_software = cpe_config.get('target_software')

            cpe_key = f'{vendor}:{product}'

            if target_software:
                cpe_key = f'{vendor}:{product}:{target_software}'

        
        if cpe_key not in cpe_to_packages_lookup:
            cpe_to_packages_lookup[cpe_key] = set()

        cpe_to_packages_lookup[cpe_key].add(name)


cve_urls = [
    'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz'
]

for year in range(2002, datetime.datetime.utcnow().year+1):
    cve_urls.append(f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz')

for url in cve_urls:
    print(f'generating for {url}...')
    cves = json.loads(gzip.decompress(requests.get(url).content))['CVE_Items']

    for cve in cves:
        cve_id =  cve['cve']['CVE_data_meta']['ID']
        description = list(filter(lambda c: c['lang'] == 'en', cve['cve']['description']['description_data']))[0]['value']
        nodes = cve.get('configurations', {}).get('nodes', [])

        for node in nodes:
            matches = node.get('cpe_match', [])

            for match in matches:
                if match.get('vulnerable'):
                    cpe_uri = match.get('cpe23Uri')
                
                    if not cpe_uri:
                        continue

                    cpe_components = cpe_uri.split(':')

                    vendor = cpe_components[3]
                    product = cpe_components[4]
                    target_software = cpe_components[10]
            
                    key1 = f'{vendor}:{product}:{target_software}'
                    key2 = f'{vendor}:{product}'
                    packages = set()

                    if key1 in cpe_to_packages_lookup:
                        for p in cpe_to_packages_lookup[key1]:
                            packages.add(p)

                    if key2 in cpe_to_packages_lookup:
                        for p in cpe_to_packages_lookup[key2]:
                            packages.add(p)

                    for package in packages:
                        version_start_including = match.get('versionStartIncluding')
                        version_end_including = match.get('versionEndIncluding')
                        version_start_excluding = match.get('versionStartExcluding')
                        version_end_excluding = match.get('versionEndExcluding')

                        v = None

                        if version_start_including:
                            if version_end_excluding:
                                v = f'>={version_start_including},<{version_end_excluding}'
                            elif version_end_including:
                                v = f'>={version_start_including},<={version_end_including}'
                            else:
                                v = f'>={version_start_including}'
                        elif version_start_excluding:
                            if version_end_excluding:
                                v = f'>{version_start_excluding},<{version_end_excluding}'
                            elif version_end_including:
                                v = f'>{version_start_excluding},<={version_end_including}'
                            else:
                                v = f'>{version_start_excluding}'
                        elif version_end_excluding:
                            v = f'<{version_end_excluding}'
                        elif version_end_including:
                            v = f'<={version_end_including}'
                        else:
                            version_component = cpe_components[5]
                            update_component = cpe_components[6]

                            if version_component not in ['*', '-']:
                                v = f'=={version_component}'
                        
                                if update_component not in ['*', '-']:
                                    v = f'=={version_component}-{update_component}'

                        if v:
                            safety_id = f'pyup.io-{cve_id}:{v}'

                            if safety_id in ids:
                                continue

                            if package not in insecure_full:
                                insecure_full[package] = []
                                insecure[package] = []

                            insecure_full[package].append(
                                {
                                    'advisory': description,
                                    'cve': cve_id,
                                    'id': safety_id,
                                    'specs': [v],
                                    'v': v,
                                }
                            )

                            insecure_full[package] = sorted(insecure_full[package], key=lambda item: item['id'])

                            if v not in insecure[package]:
                                insecure[package].append(v)
                                insecure[package] = sorted(insecure[package])

os.makedirs('./data/', exist_ok=True)

metadata = {
    'package_metadata_source': f'https://github.com/westonsteimel/package-metadata/tree/{package_metadata_revision}',
    'timestamp': int(time.time())
}

insecure_full['$meta'] = metadata
insecure['$meta'] = metadata

with open(f'./data/insecure_full.json', 'w') as f:
    json.dump(dict(sorted(insecure_full.items(), key=lambda item: item[0])), f, indent=2)

with open(f'./data/insecure.json', 'w') as f:
    json.dump(dict(sorted(insecure.items(), key=lambda item: item[0])), f, indent=2)

