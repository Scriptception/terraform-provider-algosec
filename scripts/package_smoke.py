#!/usr/bin/env python3
"""Install an actual packaged binary through a packed mirror, never an appliance.

Default: package locally built binary as a synthetic candidate ZIP. --archive:
check an existing release ZIP for this host. No signature verification is implied.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import zipfile

root = Path(__file__).resolve().parents[1]
version = (root / 'VERSION').read_text().strip()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--archive', type=Path)
args = parser.parse_args()
os_name = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows', 'FreeBSD': 'freebsd'}[platform.system()]
arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
archive_name = f'terraform-provider-algosec_{version}_{os_name}_{arch}.zip'
(root / '.local').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='package-smoke-', dir=root / '.local') as tmp:
    work = Path(tmp)
    mirror = work / 'mirror'
    package = mirror / 'registry.terraform.io/scriptception/algosec' / archive_name
    package.parent.mkdir(parents=True)
    if args.archive:
        assert args.archive.name == archive_name, f'Expected host archive {archive_name}'
        shutil.copyfile(args.archive, package)
    else:
        binary = root / 'bin/terraform-provider-algosec'
        assert binary.is_file(), 'Run make build first'
        with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(binary, f'terraform-provider-algosec_v{version}')
    cli = work / 'testing.tfrc'
    cli.write_text('provider_installation {\n filesystem_mirror {\n path = ' + json.dumps(str(mirror)) + '\n include = ["registry.terraform.io/scriptception/algosec"]\n }\n}\n')
    config = work / 'config'
    config.mkdir()
    # Real quickstart validates provider version, output attributes and read-only config.
    shutil.copyfile(root / 'examples/quickstart/main.tf', config / 'main.tf')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('ALGOSEC_', 'TF_', 'TFE_'))}
    env.update(TF_CLI_CONFIG_FILE=str(cli), TF_IN_AUTOMATION='1', CHECKPOINT_DISABLE='1')
    terraform = os.environ.get('TERRAFORM', 'terraform')
    def run(*cmd, capture=False):
        return subprocess.run([terraform, *cmd], cwd=config, env=env, check=True,
                              text=True, stdout=subprocess.PIPE if capture else None)
    run('init', '-backend=false', '-input=false', '-no-color')
    run('validate', '-no-color')
    schema = json.loads(run('providers', 'schema', '-json', capture=True).stdout)
    p = schema['provider_schemas']['registry.terraform.io/scriptception/algosec']
    assert len(p['resource_schemas']) == 2 and len(p['data_source_schemas']) == 12
    lock = (config / '.terraform.lock.hcl').read_text()
    assert f'"{version}"' in lock
    print(f'ZIP mirror init/validate/schema passed: {archive_name}; no live calls or signature verification.')
