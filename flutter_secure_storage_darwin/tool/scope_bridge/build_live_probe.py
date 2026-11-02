#!/usr/bin/env python3
"""Build and verify the signature of the production-channel gate; never launch its UI."""
import argparse
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--identity', required=True)
parser.add_argument('--profile', required=True, type=Path)
parser.add_argument('--flutter-frameworks', required=True, type=Path)
args = parser.parse_args()
profile = plistlib.loads(subprocess.check_output(['security', 'cms', '-D', '-i', str(args.profile)]))
bundle = 'cloud.igenogram.authscope.lab'
app_id = profile['Entitlements']['com.apple.application-identifier']
prefix = app_id.split('.')[0]
assert app_id in (prefix + '.*', prefix + '.' + bundle)
assert 'OSX' in profile['Platform']
here = Path(__file__).resolve().parent
package = here.parents[1]
core = package / 'darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin'
root = Path(tempfile.mkdtemp(prefix='igen-production-scope-gate-'))
app = root / 'iGen Darwin API Lab.app'
exe = app / 'Contents/MacOS/ProductionScopeLab'
exe.parent.mkdir(parents=True)
(app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
    'CFBundleIdentifier': bundle, 'CFBundleName': 'iGen Darwin API Lab',
    'CFBundleExecutable': 'ProductionScopeLab', 'CFBundlePackageType': 'APPL',
    'CFBundleVersion': '4', 'NSHighResolutionCapable': True, 'LSMinimumSystemVersion': '14.0',
}))
shutil.copy2(args.profile, app / 'Contents/embedded.provisionprofile')
rights = root / 'probe.entitlements'
rights.write_bytes(plistlib.dumps({
    'com.apple.application-identifier': prefix + '.' + bundle,
    'com.apple.developer.team-identifier': profile['TeamIdentifier'][0],
    'keychain-access-groups': [prefix + '.' + bundle],
}))
logs = Path('/tmp/igen_test_logs'); logs.mkdir(exist_ok=True)
commands = [
    ['xcrun', 'swiftc', '-swift-version', '5', '-parse-as-library', '-module-cache-path', str(root / 'module-cache'),
     '-target', 'arm64-apple-macos14.0', '-F', str(args.flutter_frameworks), '-framework', 'FlutterMacOS',
     '-Xlinker', '-rpath', '-Xlinker', str(args.flutter_frameworks),
     *map(str, sorted(core.glob('*.swift'))), str(here / 'LiveScopeProbe.swift'), '-o', str(exe)],
    ['codesign', '--force', '--sign', args.identity, '--entitlements', str(rights), str(app)],
    ['codesign', '--verify', '--deep', '--strict', str(app)],
]
for index, command in enumerate(commands):
    log = logs / f'{root.name}-{index}.log'
    with log.open('w') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        print(log.read_text())
        raise SystemExit(result.returncode)
manifest = {'app': str(app), 'launched': False, 'signature': 'verified; protected Keychain gate requires user authentication',
            'source': str(here), 'report': str(Path(tempfile.gettempdir()) / 'igen-production-scope-gate.log'),
            'scope': 'production Flutter plugin and standard method codec; no Dart engine or iGen workflow'}
(root / 'manifest.json').write_text(json.dumps(manifest, indent=2))
print(json.dumps(manifest, indent=2))
