#!/usr/bin/env python3
"""Build the native-only synthetic probe, never launch or provision it."""
from pathlib import Path
import subprocess, tempfile, plistlib, json, argparse, shutil
parser = argparse.ArgumentParser()
parser.add_argument("--identity", required=True)
parser.add_argument("--profile", type=Path, required=True)
args = parser.parse_args()
profile = plistlib.loads(subprocess.check_output(["security", "cms", "-D", "-i", str(args.profile)]))
entitlements = profile["Entitlements"]
bundle = "cloud.igenogram.authscope.lab"
app_id = entitlements["com.apple.application-identifier"]
prefix = app_id.split(".")[0]
assert app_id == prefix + ".*" or app_id == prefix + "." + bundle
assert "OSX" in profile["Platform"]
here = Path(__file__).resolve().parent
package = here.parents[1]
core = package / 'darwin/flutter_secure_storage_darwin/Sources/flutter_secure_storage_darwin'
root = Path(tempfile.mkdtemp(prefix='igen-auth-scope-probe-'))
app = root / 'iGen Auth Scope Lab.app'
exe = app / 'Contents/MacOS/AuthScopeLab'
exe.parent.mkdir(parents=True)
(app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
    'CFBundleIdentifier': 'cloud.igenogram.authscope.lab', 'CFBundleName': 'iGen Auth Scope Lab',
    'CFBundleExecutable': 'AuthScopeLab', 'CFBundlePackageType': 'APPL',
    'CFBundleVersion': '1', 'NSHighResolutionCapable': True, 'LSMinimumSystemVersion': '14.0',
}))
shutil.copy2(args.profile, app / 'Contents/embedded.provisionprofile')
rights = {'com.apple.application-identifier': prefix + '.' + bundle,
          'com.apple.developer.team-identifier': profile['TeamIdentifier'][0],
          'keychain-access-groups': [prefix + '.' + bundle]}
entitlement_file = root/'probe.entitlements'
entitlement_file.write_bytes(plistlib.dumps(rights))
logs = Path('/tmp/igen_test_logs'); logs.mkdir(exist_ok=True)
commands = [
    ['xcrun','swiftc','-swift-version','5','-D','AUTH_SCOPE_PROBE','-parse-as-library',
     '-module-cache-path',str(root/'module-cache'),'-target','arm64-apple-macos14.0',
     *[str(p) for p in sorted(core.glob('*.swift')) if p.name != 'FlutterSecureStorageDarwinPlugin.swift'],
     str(here/'AuthorizationScope.swift'),str(here/'NativePreflight.swift'),str(here/'Probe.swift'),'-o',str(exe)],
    ['codesign','--force','--sign',args.identity,'--entitlements',str(entitlement_file),str(app)],
    ['codesign','--verify','--deep','--strict',str(app)],
    [str(exe), '--preflight'],
]
for index, command in enumerate(commands):
    log = logs / f'{root.name}-{index}.log'
    with log.open('w') as stream:
        result = subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT)
    if result.returncode:
        print(log.read_text()); raise SystemExit(result.returncode)
manifest = {'app': str(app), 'launched': False, 'signing': 'Apple Development with existing provisioning profile', 'nativePreflight': 'passed; UI prohibited',
            'keychain': 'random service per run; only journal/copy synthetic items',
            'source': str(here)}
(root/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(manifest,indent=2))
