"""Read-only verification of this delivery. No operating data is modified.
Usage: python GameWeb/scripts/verify-source.py [--root EXTRACTED_ROOT]
A matching manifest is a consistency check, not a cryptographic publisher trust root.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

def verify(root: Path) -> list[str]:
    root=root.resolve(); manifest_path=root/'GameWeb/maintenance/source-manifest.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    problems=[]
    for name, expected in manifest['files'].items():
        rel=Path(name)
        if rel.is_absolute() or '..' in rel.parts:
            problems.append('Invalid manifest path: '+name); continue
        p=root/rel
        if p.is_symlink() or not p.is_file():
            problems.append('Missing or symlink: '+name); continue
        if not p.resolve().is_relative_to(root):
            problems.append('Outside source root: '+name); continue
        if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
            problems.append('Changed: '+name)
    for name in manifest.get('retiredExecutableSources',[]):
        if (root/name).exists(): problems.append('Old retired source remains: '+name)
    for p in (root/'GameConnect_Win64').rglob('*'):
        if p.is_file() and p.suffix.lower() in {'.json','.js'}:
            problems.append('JSON/JS belongs under GameWeb: '+str(p.relative_to(root)))
    return problems

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args=parser.parse_args()
    try: problems=verify(args.root)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print('SOURCE VERIFY FAILED:',type(e).__name__); return 1
    if problems:
        print('\n'.join(problems));return 1
    print('SOURCE VERIFY PASS: delivery files, retired source absence, JSON/JS placement. Not a Delphi compile or runtime security proof.')
    return 0
if __name__=='__main__': raise SystemExit(main())
