"""Read-only verification of this delivery. No operating data is modified.
Usage: python Server/tests/source/verify-source.py [--root EXTRACTED_ROOT]
A matching manifest is a consistency check, not a cryptographic publisher trust root.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

def verify(root: Path) -> list[str]:
    root=root.resolve(); manifest_path=root/'Server/maintenance/source-manifest.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    problems=[]
    if manifest.get('version') != 2 or manifest.get('algorithm') != 'sha512':
        return ['Unsupported source manifest version or algorithm']
    for name, expected in manifest['files'].items():
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts:
            problems.append('Invalid manifest path: '+name); continue
        p=root/rel
        if p.is_symlink() or not p.is_file():
            problems.append('Missing or symlink: '+name); continue
        if not p.resolve().is_relative_to(root):
            problems.append('Outside source root: '+name); continue
        if hashlib.sha512(p.read_bytes()).hexdigest()!=expected:
            problems.append('Changed: '+name)
    for name in manifest.get('retiredExecutableSources',[]):
        if (root/name).exists(): problems.append('Old retired source remains: '+name)
    native_root = root/'Desktop'
    test_root = native_root/'SpaceX.Tests'
    for p in native_root.rglob('*'):
        rel_native = p.relative_to(native_root)
        if p.is_symlink() or getattr(p, 'is_junction', lambda: False)():
            problems.append('Native source/output link is forbidden: '+p.relative_to(root).as_posix())
            continue
        parts = rel_native.parts
        if (parts[:2] == ('SpaceX.ImGui', 'SpaceX.Objects') or
                (len(parts) >= 3 and parts[0] == 'SpaceX.Tests' and parts[2] == 'SpaceX.Outputs')):
            continue
        project_output = (len(parts) >= 3 and parts[0] == 'SpaceX.Projects' and
                          parts[1] in {'SpaceX.Launcher', 'SpaceX.Client', 'SpaceX.Overlay'})
        if project_output and (parts[2].lower() == 'dcu' or
                               (len(parts) == 3 and p.is_file() and
                                parts[2].lower() == (parts[1]+'.exe').lower())):
            continue
        if not p.name.startswith('SpaceX.'):
            problems.append('Native source name must start SpaceX.: '+p.relative_to(root).as_posix())
        if not p.is_file() or p.suffix.lower() not in {'.json','.js'}:
            continue
        name = p.relative_to(root).as_posix()
        native_test_contract = (p.is_relative_to(test_root) and
                                (p.suffix.lower() == '.json' or p.name == 'SpaceX.compare-native-abi.js'))
        native_build_contract = rel_native.as_posix() in {
            'SpaceX.Source/SpaceX.Configuration/SpaceX.ReleaseMetadata.json',
            'SpaceX.Source/SpaceX.Configuration/SpaceX.StringCatalog.json',
            'SpaceX.ImGui/SpaceX.Build/SpaceX.ImGui.Abi.json',
            'SpaceX.ImGui/SpaceX.Build/SpaceX.Check-ImGui-Abi.js',
            'SpaceX.ImGui/SpaceX.Tests/SpaceX.Abi/SpaceX.test_imgui_abi.js',
            'SpaceX.Build/SpaceX.Prepare-LauncherResource.js',
            'SpaceX.Tests/SpaceX.Security/SpaceX.test-launcher-resource.js',
            'SpaceX.ImGui/SpaceX.Strings/SpaceX.NativeStrings.map.json',
            'SpaceX.ImGui/SpaceX.Assets/SpaceX.LicenseGallery/SpaceX.LicenseGallery.Reference.json',
            'SpaceX.Source/SpaceX.Configuration/SpaceX.StringUnits.map.json',
        }
        if not ((native_test_contract or native_build_contract) and name in manifest['files']):
            problems.append('JSON/JS belongs under Relay Server: '+name)
    return problems

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[3])
    args=parser.parse_args()
    try: problems=verify(args.root)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print('SOURCE VERIFY FAILED:',type(e).__name__); return 1
    if problems:
        print('\n'.join(problems));return 1
    print('SOURCE VERIFY PASS: delivery files, retired source absence, JSON/JS placement. Not a Delphi compile or runtime security proof.')
    return 0
if __name__=='__main__': raise SystemExit(main())
