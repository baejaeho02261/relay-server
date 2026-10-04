"""Read-only verification of this delivery. No operating data is modified.
Usage: python GameWeb/scripts/verify-source.py [--root EXTRACTED_ROOT]
A matching manifest is a consistency check, not a cryptographic publisher trust root.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

def verify(root: Path, require_overlay: bool = False) -> list[str]:
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
    # This one source include is regenerated from the built companion. It is
    # not exempt from checking: accept a known unprepared guard, or the exact
    # user-supplied source-only include. Neither proves the executable exists.
    # If an executable is present (or --require-overlay is used), require its
    # actual SHA-256 to match. Runtime/build identity checks are unchanged.
    for name, rule in manifest.get('generatedFiles', {}).items():
        if name != 'GameConnect_Win64/Game.Overlay.Identity.inc':
            problems.append('Unexpected generated source: '+name); continue
        p=root/name
        if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):
            problems.append('Missing or symlink: '+name); continue
        data=p.read_bytes()
        if hashlib.sha256(data).hexdigest() in [rule['unpreparedSha256'], *rule.get('previousUnpreparedSha256', [])]:
            if require_overlay:
                problems.append('Overlay identity is unprepared: '+name)
            continue  # Source package is intact; a real build is still required.
        try: content=data.decode('utf-8-sig')
        except UnicodeError:
            problems.append('Invalid generated include encoding: '+name); continue
        match=re.fullmatch(r"\{ Generated from GameOverlay.exe in this source directory; do not edit\. \}\r\nconst OverlayExpectedSHA256 = '([0-9a-f]{64})';\r\n",content)
        image=root/'GameConnect_Win64/GameOverlay.exe'
        if not match:
            problems.append('Invalid generated identity: '+name)
        elif image.is_symlink() or not image.resolve().is_relative_to(root):
            problems.append('Generated identity companion symlink or outside root: '+name)
        elif not image.is_file():
            supplied = rule.get('userSuppliedIdentity', {})
            source_only_match = (not image.exists() and
                supplied.get('includeSha256') == hashlib.sha256(data).hexdigest() and
                supplied.get('overlaySha256') == match[1])
            if require_overlay or not source_only_match:
                problems.append('Generated identity companion missing: '+name)
        elif hashlib.sha256(image.read_bytes()).hexdigest()!=match[1]:
            problems.append('Generated identity does not match companion: '+name)
    for name in manifest.get('retiredExecutableSources',[]):
        if (root/name).exists(): problems.append('Old retired source remains: '+name)
    for p in (root/'GameConnect_Win64').rglob('*'):
        if p.is_file() and p.suffix.lower() in {'.json','.js'}:
            problems.append('JSON/JS belongs under GameWeb: '+str(p.relative_to(root)))
    return problems

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--require-overlay', action='store_true', help='Also require a local GameOverlay.exe matching the generated include.')
    args=parser.parse_args()
    try: problems=verify(args.root, require_overlay=args.require_overlay)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print('SOURCE VERIFY FAILED:',type(e).__name__); return 1
    if problems:
        print('\n'.join(problems));return 1
    include=args.root/'GameConnect_Win64/Game.Overlay.Identity.inc'
    if include.is_file() and b'{$MESSAGE FATAL ' in include.read_bytes():
        print('BUILD NOT YET PREPARED: build GameOverlay.dproj in the RAD Studio IDE first, then GameConnect.dproj. No external compiler is invoked.')
    elif not (args.root/'GameConnect_Win64/GameOverlay.exe').is_file():
        print('OVERLAY EXE NOT VERIFIED: this package carries the user-supplied hash only. Preserve the matching GameOverlay.exe; use --require-overlay to verify it.')
    print('SOURCE VERIFY PASS: delivery files, retired source absence, JSON/JS placement. Not a Delphi compile or runtime security proof.')
    return 0
if __name__=='__main__': raise SystemExit(main())
